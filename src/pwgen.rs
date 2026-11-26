// Passwords and passphrases drawn at random.
//
// Every choice is uniform: each index comes from rand's Uniform, which
// rejects the values that would make some indexes likelier than others
// (Lemire's method) instead of reducing a random number modulo the count.
// A password that must hold each class of its characters is drawn whole
// and drawn again until it does, so that every password that holds them
// all is equally likely, and none is left out. Placing one character of
// each class first and filling in the rest, as some generators do, makes
// passwords that hold more classes several times likelier than others.

use rand::distr::Distribution as _;

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
// lower-case letters and digits that can't be mistaken for each other
const NONCONFUSABLE_NUMBERS: &[u8] = b"34678";
const NONCONFUSABLE_LETTERS: &[u8] = b"abcdefhjkmnpqrtuwxy";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Options {
    Password(Password),
    Passphrase(Passphrase),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Password {
    pub length: usize,
    pub characters: Characters,
    // at least one character of each class of `characters`
    pub each_class: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Characters {
    Classes {
        uppercase: bool,
        lowercase: bool,
        numbers: bool,
        symbols: bool,
    },
    // for passwords people type or write down: two classes, digits and
    // lower-case letters
    NonConfusables,
}

impl Characters {
    pub const ALL: Self = Self::Classes {
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true,
    };

    pub fn classes(self) -> Vec<&'static [u8]> {
        match self {
            Self::Classes {
                uppercase,
                lowercase,
                numbers,
                symbols,
            } => [
                (uppercase, UPPERCASE),
                (lowercase, LOWERCASE),
                (numbers, NUMBERS),
                (symbols, SYMBOLS),
            ]
            .into_iter()
            .filter_map(|(on, class)| on.then_some(class))
            .collect(),
            Self::NonConfusables => {
                vec![NONCONFUSABLE_NUMBERS, NONCONFUSABLE_LETTERS]
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passphrase {
    // words from the EFF's long list
    pub words: usize,
    pub separator: String,
    // upper-case first letters
    pub capitalize: bool,
    // a digit after one of the words
    pub number: bool,
}

pub fn pwgen(options: &Options) -> crate::error::Result<String> {
    let mut rng = rand::rng();
    match options {
        Options::Password(password) => generate_password(password, &mut rng),
        Options::Passphrase(passphrase) => {
            generate_passphrase(passphrase, &mut rng)
        }
    }
}

fn invalid(message: impl Into<String>) -> crate::error::Error {
    crate::error::Error::InvalidGeneratorOptions {
        message: message.into(),
    }
}

// A uniform index below `count`.
fn indexes(
    count: usize,
) -> crate::error::Result<rand::distr::Uniform<usize>> {
    rand::distr::Uniform::new(0, count)
        .map_err(|_| invalid("nothing to choose from"))
}

fn generate_password(
    password: &Password,
    rng: &mut impl rand::Rng,
) -> crate::error::Result<String> {
    let classes = password.characters.classes();
    if password.each_class && password.length < classes.len() {
        return Err(invalid(format!(
            "a password of {} characters can't hold one of each of its {} \
            character classes",
            password.length,
            classes.len()
        )));
    }
    let alphabet = classes.concat();
    let index = indexes(alphabet.len())
        .map_err(|_| invalid("no characters to make a password of"))?;
    let required = if password.each_class {
        &classes[..]
    } else {
        &[]
    };
    let mut chars = Vec::with_capacity(password.length);
    loop {
        chars.clear();
        chars.extend((0..password.length).map(|_| index.sample(rng)));
        if let Some(text) = accept(&alphabet, required, &chars) {
            return Ok(text);
        }
    }
}

// The password that the indexes into the alphabet spell, if it holds a
// character of each required class.
fn accept(
    alphabet: &[u8],
    required: &[&[u8]],
    indexes: &[usize],
) -> Option<String> {
    let text: Vec<u8> =
        indexes.iter().map(|&index| alphabet[index]).collect();
    required
        .iter()
        .all(|class| text.iter().any(|c| class.contains(c)))
        // the alphabet is ASCII
        .then(|| String::from_utf8(text).unwrap())
}

fn generate_passphrase(
    passphrase: &Passphrase,
    rng: &mut impl rand::Rng,
) -> crate::error::Result<String> {
    if passphrase.separator.chars().any(char::is_control) {
        return Err(invalid("the separator holds control characters"));
    }
    let word = indexes(crate::wordlist::EFF_LONG.len())?;
    let mut words: Vec<String> = (0..passphrase.words)
        .map(|_| {
            let word = crate::wordlist::EFF_LONG[word.sample(rng)];
            if passphrase.capitalize {
                capitalize(word)
            } else {
                word.to_string()
            }
        })
        .collect();
    if passphrase.number {
        let at = indexes(words.len()).map_err(|_| {
            invalid("a passphrase needs a word to put a number after")
        })?;
        let digit = indexes(NUMBERS.len())?;
        words[at.sample(rng)].push(char::from(NUMBERS[digit.sample(rng)]));
    }
    Ok(words.join(&passphrase.separator))
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

#[cfg(test)]
mod test {
    use super::*;

    fn password(characters: Characters, each_class: bool) -> Password {
        Password {
            length: 0,
            characters,
            each_class,
        }
    }

    fn classes(
        uppercase: bool,
        lowercase: bool,
        numbers: bool,
        symbols: bool,
    ) -> Characters {
        Characters::Classes {
            uppercase,
            lowercase,
            numbers,
            symbols,
        }
    }

    fn sorted(characters: Characters) -> Vec<u8> {
        let mut all = characters.classes().concat();
        all.sort_unstable();
        all
    }

    // what --no-symbols, --only-numbers and the default picked from before
    // they became classes
    #[test]
    fn the_old_character_sets_stay_the_same() {
        let printable: Vec<u8> = (b'!'..=b'~').collect();
        assert_eq!(sorted(Characters::ALL), printable);
        let alphanumeric: Vec<u8> = printable
            .iter()
            .copied()
            .filter(u8::is_ascii_alphanumeric)
            .collect();
        assert_eq!(sorted(classes(true, true, true, false)), alphanumeric);
        assert_eq!(sorted(classes(false, false, true, false)), b"0123456789");
        assert_eq!(
            sorted(Characters::NonConfusables),
            b"34678abcdefhjkmnpqrtuwxy"
        );
        // no character is in two classes, so each is as likely as another
        for characters in [Characters::ALL, Characters::NonConfusables] {
            let mut all = sorted(characters);
            all.dedup();
            assert_eq!(all.len(), characters.classes().concat().len());
        }
    }

    // Every sequence of indexes is one draw, all equally likely. Going
    // through all of them shows which passwords come out and how often.
    fn outcomes(
        alphabet: &[u8],
        required: &[&[u8]],
        length: u32,
    ) -> std::collections::HashMap<String, usize> {
        let count = alphabet.len();
        let mut outcomes = std::collections::HashMap::new();
        for draw in 0..count.pow(length) {
            let indexes: Vec<usize> =
                (0..length).map(|i| draw / count.pow(i) % count).collect();
            if let Some(text) = accept(alphabet, required, &indexes) {
                *outcomes.entry(text).or_insert(0) += 1;
            }
        }
        outcomes
    }

    #[test]
    fn requiring_each_class_keeps_every_password_that_has_them_equally_likely(
    ) {
        let classes: [&[u8]; 3] = [b"ab", b"0", b"#$%"];
        let alphabet = classes.concat();
        for length in 0..=5 {
            let outcomes = outcomes(&alphabet, &classes, length);
            // each comes from one draw, so all are equally likely
            assert!(outcomes.values().all(|&draws| draws == 1));
            // and they are all the passwords of that length that hold every
            // class: inclusion-exclusion over the classes left out
            let (mut added, mut taken) = (0, 0);
            for left_out in 0..(1 << classes.len()) {
                let missing: usize = (0..classes.len())
                    .filter(|i| left_out & (1 << i) != 0)
                    .map(|i| classes[i].len())
                    .sum();
                let count = (alphabet.len() - missing).pow(length);
                if u32::count_ones(left_out) % 2 == 0 {
                    added += count;
                } else {
                    taken += count;
                }
            }
            assert_eq!(outcomes.len(), added - taken, "length {length}");
            for text in outcomes.keys() {
                assert!(classes
                    .iter()
                    .all(|class| text.bytes().any(|c| class.contains(&c))));
            }
        }
        // without the requirement, every password comes out
        assert_eq!(outcomes(&alphabet, &[], 3).len(), 6usize.pow(3));
    }

    #[test]
    fn passwords_hold_what_they_must() {
        let mut rng = rand::rng();
        for characters in [
            Characters::ALL,
            classes(true, true, false, false),
            classes(true, true, false, true),
            classes(false, false, true, false),
            Characters::NonConfusables,
        ] {
            let allowed = characters.classes().concat();
            for length in [4, 12, 30] {
                let options = Password {
                    length,
                    ..password(characters, true)
                };
                for _ in 0..50 {
                    let text = generate_password(&options, &mut rng).unwrap();
                    assert_eq!(text.len(), length);
                    assert!(text.bytes().all(|c| allowed.contains(&c)));
                    for class in characters.classes() {
                        assert!(text.bytes().any(|c| class.contains(&c)));
                    }
                }
            }
        }
    }

    #[test]
    fn impossible_passwords_are_refused() {
        let mut rng = rand::rng();
        let too_short = Password {
            length: 3,
            ..password(Characters::ALL, true)
        };
        assert!(generate_password(&too_short, &mut rng).is_err());
        let fits = Password {
            length: 4,
            ..too_short
        };
        assert!(generate_password(&fits, &mut rng).is_ok());
        let nothing = Password {
            length: 8,
            ..password(classes(false, false, false, false), false)
        };
        assert!(generate_password(&nothing, &mut rng).is_err());
        let empty = password(Characters::ALL, false);
        assert_eq!(generate_password(&empty, &mut rng).unwrap(), "");
    }

    fn passphrase(words: usize) -> Passphrase {
        Passphrase {
            words,
            separator: " ".to_string(),
            capitalize: false,
            number: false,
        }
    }

    #[test]
    fn passphrases_take_their_options() {
        let mut rng = rand::rng();
        let plain = generate_passphrase(&passphrase(5), &mut rng).unwrap();
        let words: Vec<_> = plain.split(' ').collect();
        assert_eq!(words.len(), 5);
        assert!(words
            .iter()
            .all(|word| crate::wordlist::EFF_LONG.contains(word)));

        let options = Passphrase {
            separator: "_".to_string(),
            capitalize: true,
            number: true,
            ..passphrase(4)
        };
        for _ in 0..50 {
            let text = generate_passphrase(&options, &mut rng).unwrap();
            let words: Vec<_> = text.split('_').collect();
            assert_eq!(words.len(), 4);
            assert_eq!(
                text.bytes().filter(u8::is_ascii_digit).count(),
                1,
                "{text}"
            );
            for word in words {
                assert!(word.starts_with(|c: char| c.is_ascii_uppercase()));
                let word = word
                    .trim_end_matches(|c: char| c.is_ascii_digit())
                    .to_lowercase();
                assert!(crate::wordlist::EFF_LONG.contains(&word.as_str()));
            }
        }

        let bad = Passphrase {
            separator: "\n".to_string(),
            ..passphrase(4)
        };
        assert!(generate_passphrase(&bad, &mut rng).is_err());
        let no_words = Passphrase {
            number: true,
            ..passphrase(0)
        };
        assert!(generate_passphrase(&no_words, &mut rng).is_err());
    }

    // A passphrase reads back into its words whatever the separator, also
    // none, since no word of the list begins another: the first word is the
    // only one the passphrase begins with, and so on. So different choices
    // make different passphrases, and a passphrase holds all the randomness
    // of its words, the word with the number and the number.
    #[test]
    fn no_word_begins_another() {
        let mut words = crate::wordlist::EFF_LONG.to_vec();
        words.sort_unstable();
        for pair in words.windows(2) {
            assert!(!pair[1].starts_with(pair[0]), "{pair:?}");
        }
        assert!(words.iter().all(|word| word
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c == b'-')));
    }

    #[test]
    fn capitalizing_changes_only_the_first_letter() {
        assert_eq!(capitalize("t-shirt"), "T-shirt");
        assert_eq!(capitalize(""), "");
    }
}
