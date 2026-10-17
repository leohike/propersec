//! The one file format: `key = value` lines. Blank lines and `#` comments are skipped; anything
//! else is an error. Keys keep their order, so a file written back reads the same.

use crate::Error;

pub type Pairs = Vec<(String, String)>;

pub fn parse(text: &str, source: &str) -> Result<Pairs, Error> {
    let mut pairs = Pairs::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index + 1;
        let syntax = || Error::Syntax { file: source.into(), line: number };
        let (key, value) = line.split_once('=').ok_or_else(syntax)?;
        let (key, value) = (key.trim(), value.trim());
        if key.is_empty() || value.is_empty() {
            return Err(syntax());
        }
        if pairs.iter().any(|(existing, _)| existing == key) {
            return Err(Error::Duplicate { file: source.into(), line: number, key: key.into() });
        }
        pairs.push((key.into(), value.into()));
    }
    Ok(pairs)
}

pub fn format(pairs: &[(String, String)]) -> String {
    pairs.iter().map(|(key, value)| format!("{key} = {value}\n")).collect()
}

/// Plain ASCII digits only: no sign, no spaces, no "²".
pub(crate) fn digits<T: std::str::FromStr>(text: &str) -> Option<T> {
    text.bytes().all(|byte| byte.is_ascii_digit()).then(|| text.parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_comments_and_blanks_and_trims() {
        let pairs = parse("# a comment\n\nmax_failures = 5\n  hash_cost=6  \n", "f").unwrap();
        assert_eq!(pairs, vec![("max_failures".into(), "5".into()), ("hash_cost".into(), "6".into())]);
    }

    #[test]
    fn refuses_what_is_not_a_pair() {
        for text in ["just words\n", "= 5\n", "key =\n"] {
            assert!(matches!(parse(text, "f"), Err(Error::Syntax { .. })), "{text:?}");
        }
    }

    #[test]
    fn refuses_a_key_given_twice() {
        assert!(matches!(parse("a = 1\na = 2\n", "f"), Err(Error::Duplicate { .. })));
    }

    #[test]
    fn round_trips() {
        let pairs = parse("hash = old\nmax_failures = 2\n", "f").unwrap();
        assert_eq!(format(&pairs), "hash = old\nmax_failures = 2\n");
    }
}
