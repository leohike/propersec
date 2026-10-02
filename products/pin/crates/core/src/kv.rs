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

/// `pairs` with `key` set to `value`: replaced where it was, or added at the end.
pub fn with(mut pairs: Pairs, key: &str, value: &str) -> Pairs {
    match pairs.iter_mut().find(|(existing, _)| existing == key) {
        Some((_, existing)) => *existing = value.into(),
        None => pairs.push((key.into(), value.into())),
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_comments_and_blanks_and_trims() {
        let pairs = parse("# a comment\n\nmax_failures = 5\n  expiry_hours=2  \n", "f").unwrap();
        assert_eq!(pairs, vec![("max_failures".into(), "5".into()), ("expiry_hours".into(), "2".into())]);
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
    fn round_trips_and_replaces_in_place() {
        let pairs = with(parse("hash = old\nmax_failures = 2\n", "f").unwrap(), "hash", "new");
        assert_eq!(format(&pairs), "hash = new\nmax_failures = 2\n");
    }
}
