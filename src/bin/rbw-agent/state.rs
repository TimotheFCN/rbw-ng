// How long an entry with master password reprompt stays open after it was
// unlocked or last read. The official clients ask again each time such an
// entry is opened and keep it open while it is shown; a program that shows
// one keeps reading it, at least to refresh its code every period.
const ENTRY_UNLOCK_IDLE: std::time::Duration =
    std::time::Duration::from_secs(120);

// A use measured on both clocks, so that neither a sleep (which the
// monotonic clock skips) nor a clock change (which the wall clock follows)
// keeps an entry open longer.
#[derive(Clone, Copy)]
pub struct LastUse {
    instant: std::time::Instant,
    time: std::time::SystemTime,
}

impl LastUse {
    fn now() -> Self {
        Self {
            instant: std::time::Instant::now(),
            time: std::time::SystemTime::now(),
        }
    }

    fn expired(self) -> bool {
        self.instant.elapsed() >= ENTRY_UNLOCK_IDLE
            || self
                .time
                .elapsed()
                .map_or(true, |elapsed| elapsed >= ENTRY_UNLOCK_IDLE)
    }
}

pub struct State {
    pub priv_key: Option<rbw::locked::Keys>,
    pub org_keys:
        Option<std::collections::HashMap<String, rbw::locked::Keys>>,
    pub timeout: crate::timeout::Timeout,
    pub timeout_duration: std::time::Duration,
    pub sync_timeout: crate::timeout::Timeout,
    pub sync_timeout_duration: std::time::Duration,
    pub notifications_handler: crate::notifications::Handler,
    // the values that need the master password again (see reprompt.rs),
    // or None until the agent knows them from a sync or from a local copy
    // of the vault that carries its MAC
    pub master_password_reprompt: Option<crate::reprompt::Protected>,
    // entries that rbw item unlock opened, by id, with when they were
    // last read
    pub unlocked_entries: std::collections::HashMap<String, LastUse>,
    pub unlock_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    #[cfg(target_os = "macos")]
    // Read at startup and when `rbw config` changes it, so that a password
    // unlock doesn't reread the config.
    pub touch_id_unlock: bool,
    // Ask before every SSH signature, kept the same way.
    pub ssh_confirm: bool,
    #[cfg(target_os = "macos")]
    pub biometric_unlock: Option<std::sync::Arc<crate::biometric::Session>>,

    // this is stored here specifically for the use of the ssh agent, because
    // requests made to the ssh agent don't include an environment, and so we
    // can't properly initialize the pinentry process. we work around this by
    // just reusing the last environment we saw being sent to the main agent
    // (there should be at least one in most cases because you need to start
    // the rbw agent in order to make it start serving on the ssh agent
    // socket, and that initial request should come with an environment).
    //
    // we should not use this for any requests on the main agent, those
    // should all send their own environment over.
    pub last_environment: rbw::protocol::Environment,

    #[cfg(feature = "clipboard")]
    pub clipboard: Option<arboard::Clipboard>,
}

impl State {
    pub fn key(&self, org_id: Option<&str>) -> Option<&rbw::locked::Keys> {
        org_id.map_or(self.priv_key.as_ref(), |id| {
            self.org_keys.as_ref().and_then(|h| h.get(id))
        })
    }

    pub fn needs_unlock(&self) -> bool {
        self.priv_key.is_none() || self.org_keys.is_none()
    }

    pub fn set_timeout(&self) {
        self.timeout.set(self.timeout_duration);
    }

    // The lock timer only notices a wake from sleep after a few seconds, so
    // check its deadline before serving a request.
    pub fn lock_if_expired(&mut self) {
        if self.timeout.expired() {
            self.clear();
        }
    }

    pub fn clear(&mut self) {
        self.priv_key = None;
        self.org_keys = None;
        self.unlocked_entries.clear();
        self.timeout.clear();
    }

    pub fn unlock_entry(&mut self, id: &str) {
        self.unlocked_entries
            .insert(id.to_ascii_lowercase(), LastUse::now());
    }

    // Whether rbw item unlock opened the entry and it is still open; reading
    // it keeps it open.
    pub fn use_unlocked_entry(&mut self, id: &str) -> bool {
        let id = id.to_ascii_lowercase();
        match self.unlocked_entries.get(&id) {
            Some(last_use) if !last_use.expired() => {
                self.unlocked_entries.insert(id, LastUse::now());
                true
            }
            Some(_) => {
                self.unlocked_entries.remove(&id);
                false
            }
            None => false,
        }
    }

    pub fn clear_all(&mut self) {
        self.clear();
        #[cfg(target_os = "macos")]
        {
            self.biometric_unlock = None;
        }
    }

    pub fn set_sync_timeout(&self) {
        self.sync_timeout.set(self.sync_timeout_duration);
    }

    // Learns which values need the master password again from entries the
    // agent synced from the server.
    pub fn set_master_password_reprompt(
        &mut self,
        entries: &[rbw::db::Entry],
    ) {
        self.master_password_reprompt =
            Some(crate::reprompt::protected(entries));
    }

    // Learns them from the local copy of the vault, if it carries the
    // agent's MAC of them under the vault key, so that no other program
    // changed them.
    pub fn trust_master_password_reprompt(&mut self, db: &rbw::db::Db) {
        let (Some(keys), Some(mac)) = (&self.priv_key, &db.reprompt_mac)
        else {
            return;
        };
        let protected = crate::reprompt::protected(&db.entries);
        if crate::reprompt::verify(keys, &protected, mac) {
            self.master_password_reprompt = Some(protected);
        }
    }

    // The MAC that lets a later agent trust the local copy of the vault,
    // when the vault is unlocked and the agent knows the protected values.
    pub fn master_password_reprompt_mac(&self) -> Option<String> {
        Some(crate::reprompt::mac(
            self.priv_key.as_ref()?,
            self.master_password_reprompt.as_ref()?,
        ))
    }

    pub fn last_environment(&self) -> &rbw::protocol::Environment {
        &self.last_environment
    }

    pub fn set_last_environment(
        &mut self,
        environment: rbw::protocol::Environment,
    ) {
        self.last_environment = environment;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn an_unlocked_entry_closes_once_unread_on_either_clock() {
        assert!(!LastUse::now().expired());
        let now = LastUse::now();
        let slept = LastUse {
            time: now.time - ENTRY_UNLOCK_IDLE,
            ..now
        };
        assert!(slept.expired());
        let clock_set_back = LastUse {
            time: now.time + ENTRY_UNLOCK_IDLE,
            ..now
        };
        assert!(clock_set_back.expired());
        if let Some(instant) = now.instant.checked_sub(ENTRY_UNLOCK_IDLE) {
            assert!(LastUse { instant, ..now }.expired());
        }
    }
}
