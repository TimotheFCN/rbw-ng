// One-time codes (TOTP) from the secret Bitwarden stores with a login: a
// base32 secret, an otpauth://totp/ address or a steam:// address.

use anyhow::Context as _;

const TOTP_DEFAULT_STEP: u64 = 30;

// A code and the time window it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub code: String,
    // seconds
    pub period: u64,
    // Unix time, in seconds, when the next code starts
    pub expires_at: u64,
}

// The code for the current time.
pub fn current(secret: &str) -> anyhow::Result<Code> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the system clock is set before 1970")?
        .as_secs();
    at(secret, now)
}

// The code for the given Unix time, in seconds.
pub fn at(secret: &str, time: u64) -> anyhow::Result<Code> {
    let params = parse_totp_secret(secret)?;
    let period = params.period;
    let code = generate_totp_at(params, time)?;
    Ok(Code {
        code,
        period,
        expires_at: (time / period + 1) * period,
    })
}

struct TotpParams {
    secret: Vec<u8>,
    algorithm: String,
    digits: u8,
    period: u64,
}

fn decode_totp_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    let secret = secret.trim().replace(' ', "");
    let alphabets = [
        base32::Alphabet::Rfc4648 { padding: false },
        base32::Alphabet::Rfc4648 { padding: true },
        base32::Alphabet::Rfc4648Lower { padding: false },
        base32::Alphabet::Rfc4648Lower { padding: true },
    ];
    for alphabet in alphabets {
        if let Some(secret) = base32::decode(alphabet, &secret) {
            return Ok(secret);
        }
    }
    Err(anyhow::anyhow!("totp secret was not valid base32"))
}

fn parse_totp_secret(secret: &str) -> anyhow::Result<TotpParams> {
    if let Ok(u) = url::Url::parse(secret) {
        match u.scheme() {
            "otpauth" => {
                if u.host_str() != Some("totp") {
                    return Err(anyhow::anyhow!(
                        "totp secret url must have totp host"
                    ));
                }

                let query: std::collections::HashMap<_, _> =
                    u.query_pairs().collect();

                let secret = decode_totp_secret(
                    query.get("secret").ok_or_else(|| {
                        anyhow::anyhow!("totp secret url must have secret")
                    })?,
                )?;
                let algorithm = query.get("algorithm").map_or_else(
                    || String::from("SHA1"),
                    std::string::ToString::to_string,
                );
                let digits = match query.get("digits") {
                    Some(dig) => dig
                        .parse::<usize>()
                        .map_err(|_| anyhow::anyhow!("digits parameter in totp url must be a valid integer."))?,
                    None => 6,
                };
                let period = match query.get("period") {
                    Some(dig) => {
                        dig.parse::<u64>().map_err(|_| anyhow::anyhow!("period parameter in totp url must be a valid integer."))?
                    }
                    None => TOTP_DEFAULT_STEP,
                };
                // a code is the HOTP value modulo 10^digits, which has to
                // fit in 32 bits
                let digits = u8::try_from(digits)
                    .ok()
                    .filter(|digits| (1..=9).contains(digits))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "digits parameter in totp url must be between 1 \
                             and 9"
                        )
                    })?;
                if period == 0 {
                    return Err(anyhow::anyhow!(
                        "period parameter in totp url must be greater than 0"
                    ));
                }

                Ok(TotpParams {
                    secret,
                    algorithm,
                    digits,
                    period,
                })
            }
            "steam" => {
                let steam_secret = u.host_str().ok_or_else(|| {
                    anyhow::anyhow!("steam totp url must have a secret")
                })?;

                Ok(TotpParams {
                    secret: decode_totp_secret(steam_secret)?,
                    algorithm: String::from("STEAM"),
                    digits: 5,
                    period: TOTP_DEFAULT_STEP,
                })
            }
            _ => Err(anyhow::anyhow!(
                "totp secret url must have 'otpauth' or 'steam' scheme"
            )),
        }
    } else {
        Ok(TotpParams {
            secret: decode_totp_secret(secret)?,
            algorithm: String::from("SHA1"),
            digits: 6,
            period: TOTP_DEFAULT_STEP,
        })
    }
}

// This function exists for the sake of making the generate_totp function less
// densely packed and more readable
fn generate_totp_algorithm_type(
    alg: &str,
) -> anyhow::Result<totp_rs::Algorithm> {
    match alg {
        "SHA1" => Ok(totp_rs::Algorithm::SHA1),
        "SHA256" => Ok(totp_rs::Algorithm::SHA256),
        "SHA512" => Ok(totp_rs::Algorithm::SHA512),
        "STEAM" => Ok(totp_rs::Algorithm::Steam),
        _ => Err(anyhow::anyhow!(format!("{alg} is not a valid algorithm"))),
    }
}

pub fn generate_totp(secret: &str) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the system clock is set before 1970")?
        .as_secs();
    generate_totp_at(parse_totp_secret(secret)?, now)
}

// The code for the given Unix time, in seconds.
fn generate_totp_at(
    totp_params: TotpParams,
    time: u64,
) -> anyhow::Result<String> {
    let alg = totp_params.algorithm.as_str();

    match alg {
        "SHA1" | "SHA256" | "SHA512" => Ok(totp_rs::Builder::new()
            .with_algorithm(generate_totp_algorithm_type(alg)?)
            .with_digits(totp_params.digits)
            .with_skew(1) // the library docs say this should be a 1
            .with_step_duration(totp_params.period)
            .with_secret(totp_params.secret)
            .build_noncompliant()
            .generate(time)
            .to_string()),
        // build() would refuse secrets shorter than 128 bits, which
        // totp-rs 5 accepted
        "STEAM" => Ok(totp_rs::Builder::new_steam()
            .with_secret(totp_params.secret)
            .build_noncompliant()
            .generate(time)
            .to_string()),
        _ => Err(anyhow::anyhow!(format!(
            "{alg} is not a valid totp algorithm"
        ))),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_decode_totp_secret() {
        let decoded = decode_totp_secret("NBSW Y3DP EB3W 64TM MQQQ").unwrap();
        let want = b"hello world!".to_vec();
        assert!(decoded == want, "strips spaces");
    }

    #[track_caller]
    fn totp_at(secret: &str, time: u64) -> String {
        generate_totp_at(parse_totp_secret(secret).unwrap(), time).unwrap()
    }

    // The test vectors of RFC 6238, appendix B: the ASCII secret
    // "12345678901234567890" repeated to the hash's block size, 8 digits,
    // 30 second steps.
    const RFC6238_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const RFC6238_SHA256: &str =
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const RFC6238_SHA512: &str =
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
         GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";
    const RFC6238_VECTORS: &[(u64, &str, &str, &str)] = &[
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn test_totp_rfc6238_vectors() {
        for &(time, sha1, sha256, sha512) in RFC6238_VECTORS {
            let url = |alg: &str, secret: &str| {
                format!(
                    "otpauth://totp/rbw?secret={secret}&algorithm={alg}\
                     &digits=8&period=30"
                )
            };
            assert_eq!(totp_at(&url("SHA1", RFC6238_SHA1), time), sha1);
            assert_eq!(totp_at(&url("SHA256", RFC6238_SHA256), time), sha256);
            assert_eq!(totp_at(&url("SHA512", RFC6238_SHA512), time), sha512);
        }
    }

    #[test]
    fn test_totp_plain_secret_forms() {
        // a bare secret means SHA1, 6 digits and 30 second steps, which
        // are the last 6 digits of the 8 digit SHA1 vectors
        for &(time, sha1, _, _) in RFC6238_VECTORS {
            let want = &sha1[2..];
            for secret in [
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
                "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
                "  gezd gnbv gy3t qojq gezd gnbv gy3t qojq\n",
            ] {
                assert_eq!(totp_at(secret, time), want, "{secret:?}");
            }
        }

        // padded and unpadded base32
        let time = 1_234_567_890;
        let padded =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
        assert_eq!(totp_at(padded, time), "012961");
        assert_eq!(totp_at(padded.trim_end_matches('='), time), "012961");
        assert_eq!(
            totp_at(&padded.to_lowercase(), time),
            totp_at(padded, time)
        );

        // secrets shorter than the 128 bits RFC 4226 asks for still work
        assert_eq!(totp_at("GAYTEMZUGU3DOOBZ", time), "625421");
        // and so does an empty one
        assert_eq!(totp_at("", time), "712049");
    }

    #[test]
    fn test_totp_otpauth_parameters() {
        let time = 1_234_567_890;
        // defaults: SHA1, 6 digits, 30 seconds
        assert_eq!(
            totp_at(
                &format!("otpauth://totp/rbw?secret={RFC6238_SHA1}"),
                time
            ),
            "005924"
        );
        // lowercase secret, label with an issuer, other parameters
        assert_eq!(
            totp_at(
                "otpauth://totp/Example:alice@example.com?\
                 secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&issuer=Example",
                time
            ),
            "005924"
        );
        // 7 and 9 digits, 60 second steps
        assert_eq!(
            totp_at(
                &format!(
                    "otpauth://totp/rbw?secret={RFC6238_SHA256}\
                     &algorithm=SHA256&digits=7&period=60"
                ),
                time
            ),
            "6450756"
        );
        assert_eq!(
            totp_at(
                &format!("otpauth://totp/rbw?secret={RFC6238_SHA1}&digits=9"),
                time
            ),
            "689005924"
        );
        // a 60 second step is the 30 second code of half the time
        assert_eq!(
            totp_at(
                &format!(
                    "otpauth://totp/rbw?secret={RFC6238_SHA1}&digits=8\
                     &period=60"
                ),
                118
            ),
            "94287082"
        );
        // spaces in the secret, encoded as + or %20
        assert_eq!(
            totp_at(
                "otpauth://totp/rbw?secret=GEZD+GNBV%20GY3T+QOJQ\
                 +GEZDGNBVGY3TQOJQ",
                time
            ),
            "005924"
        );
    }

    #[test]
    fn test_totp_steam() {
        // computed independently: the SHA1 HOTP value written in Steam's
        // 26 character alphabet, 5 characters
        let steam = [
            (59, "PV9M4"),
            (1_111_111_109, "PY4YB"),
            (1_111_111_111, "5PP3V"),
            (1_234_567_890, "VHHQY"),
            (2_000_000_000, "9N776"),
            (20_000_000_000, "R5DMB"),
        ];
        // a secret shorter than RFC 4226 asks for, as for the other
        // algorithms
        assert_eq!(totp_at("steam://GAYTEMZUGU3DOOBZ", 59), "CDH7P");
        for (time, want) in steam {
            assert_eq!(
                totp_at(&format!("steam://{RFC6238_SHA1}"), time),
                want
            );
            assert_eq!(
                totp_at(
                    &format!(
                        "otpauth://totp/Steam:alice?secret={RFC6238_SHA1}\
                         &algorithm=STEAM"
                    ),
                    time
                ),
                want
            );
        }
    }

    #[test]
    fn test_totp_rejected_secrets() {
        for secret in [
            "not base32!",
            "otpauth://hotp/rbw?secret=GEZDGNBV",
            "otpauth://totp/rbw",
            "otpauth://totp/rbw?secret=GEZDGNBV&digits=six",
            "otpauth://totp/rbw?secret=GEZDGNBV&period=-30",
            "otpauth://totp/rbw?secret=GEZDGNBV&algorithm=MD5",
            "https://example.com/?secret=GEZDGNBV",
            // these used to panic or give a code of the wrong length
            "otpauth://totp/rbw?secret=GEZDGNBV&digits=0",
            "otpauth://totp/rbw?secret=GEZDGNBV&digits=10",
            "otpauth://totp/rbw?secret=GEZDGNBV&digits=300",
            "otpauth://totp/rbw?secret=GEZDGNBV&period=0",
            "steam:GEZDGNBV",
        ] {
            assert!(
                parse_totp_secret(secret)
                    .and_then(|params| generate_totp_at(params, 59))
                    .is_err(),
                "{secret:?}"
            );
        }
    }

    #[test]
    fn test_code_window() {
        let code = at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
        assert_eq!(code.period, 30);
        assert_eq!(code.expires_at, 60);
        assert_eq!(code.code.len(), 6);
        let code =
            at("otpauth://totp/x?secret=GEZDGNBV&period=60", 61).unwrap();
        assert_eq!(code.expires_at, 120);
    }
}
