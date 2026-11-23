// Whether a login's address matches the address of a page, by the match
// type stored with the address (Bitwarden's "URI match detection").

pub fn matches(
    url: &str,
    match_type: Option<crate::api::UriMatchType>,
    given_url: &url::Url,
) -> bool {
    match match_type.unwrap_or(crate::api::UriMatchType::Domain) {
        crate::api::UriMatchType::Domain => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && (self_host_port == given_host_port
                            || given_host_port
                                .ends_with(&format!(".{self_host_port}")))
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
                || given_host_port.ends_with(&format!(".{url}"))
        }
        crate::api::UriMatchType::Host => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && self_host_port == given_host_port
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
        }
        crate::api::UriMatchType::StartsWith => {
            given_url.to_string().starts_with(url)
        }
        crate::api::UriMatchType::Exact => {
            if given_url.path() == "/" {
                given_url.to_string().trim_end_matches('/')
                    == url.trim_end_matches('/')
            } else {
                given_url.to_string() == url
            }
        }
        crate::api::UriMatchType::RegularExpression => {
            let Ok(rx) = regex::Regex::new(url) else {
                return false;
            };
            rx.is_match(given_url.as_ref())
        }
        crate::api::UriMatchType::Never => false,
    }
}

fn host_port(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        url.port().map_or_else(
            || host.to_string(),
            |port| format!("{host}:{port}"),
        ),
    )
}
