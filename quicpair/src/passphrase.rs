use crate::{ClientId, Signature};
use anyhow::{Context, Result};
use std::{collections::HashMap, io::Read, sync::LazyLock};

const LEN: usize = 10322;
static WORDLIST: LazyLock<(Box<[&str]>, HashMap<&str, usize>)> = LazyLock::new(|| {
    static WORDLIST_GZIPPED: &[u8] = include_bytes!("./wordlist.gz");

    let mut reader = WORDLIST_GZIPPED;
    let mut decoder = flate2::read::GzDecoder::new(&mut reader);

    // current number of chars in the file (zcat wordlist.gz | wc -c)
    let mut string = String::with_capacity(71482);

    decoder.read_to_string(&mut string).unwrap();

    let str = Box::leak(string.into_boxed_str());

    // current number of lines in the file (zcat wordlist.gz | wc -l)
    let mut words = Vec::with_capacity(LEN);
    words.extend(str.trim().split('\n'));

    assert_eq!(words.len(), LEN, "whoops");

    let words = words.into_boxed_slice();

    let mut reverse_map = HashMap::new();
    for (i, &word) in words.iter().enumerate() {
        reverse_map.insert(word, i);
    }

    (words, reverse_map)
});

impl Signature {
    pub fn to_passphrase(self) -> String {
        let wordlist = &WORDLIST.0;
        assert_eq!(wordlist.len(), LEN, "unreachable");

        // log2(10322) ≈ 80/6 so 6 words >= 80 bits of entropy
        let num_words = 6;

        let mut num = self.0;
        let mut res = String::new();
        for i in 0..num_words {
            res.push_str(wordlist[(num % LEN as u128) as usize]);
            num /= LEN as u128;
            if i < num_words - 1 {
                res.push(' ');
            }
        }

        res
    }
    pub fn from_passphrase(passphrase: &str) -> Result<Self> {
        let passphrase = passphrase.trim().to_ascii_lowercase();

        let map = &WORDLIST.1;

        let mut num_words_processed = 0;
        let mut result: u128 = 0;
        for word in passphrase.rsplit(' ') {
            let index = *map
                .get(word)
                .with_context(|| format!("invalid word {word}"))?;
            result = result * LEN as u128 + index as u128;
            num_words_processed += 1;
        }

        if num_words_processed != 6 {
            anyhow::bail!("passphrases must contain exactly 6 words");
        }

        Self::from_u128(result).context("invalid passphrase")
    }
}
impl ClientId {
    pub fn to_word(self) -> String {
        let wordlist = &WORDLIST.0;
        assert_eq!(wordlist.len(), LEN, "unreachable");
        assert!(self.0 < Self::MAX_CLIENT_ID, "unreachable");

        wordlist[self.0 as usize].into()
    }
    pub fn from_word(word: &str) -> Result<Self> {
        let word = word.trim().to_ascii_lowercase();

        let map = &WORDLIST.1;

        let val = map
            .get(&*word)
            .and_then(|&val| (val < Self::MAX_CLIENT_ID as usize).then_some(val))
            .with_context(|| format!("invalid word {word:?}"))?;

        Ok(Self(val as _))
    }
}

#[cfg(test)]
mod tests {
    use crate::Signature;
    use anyhow::Result;

    #[test]
    pub fn test_key() -> Result<()> {
        for val in [
            0u128,
            42u128,
            9001u128,
            0x10101010101010101010u128,
            0xffffffffffffffffffffu128,
        ] {
            let key = Signature::from_u128(val).unwrap();
            let string = key.to_passphrase();
            let new_key = Signature::from_passphrase(&string)?;

            assert_eq!(
                key, new_key,
                "key {key:?} failed encode/decode test: encoded to {string:?}"
            );
        }

        for phrase in [
            "invalid invalid invalid invalid invalid asjfadsfksajdfkasjdf",
            "",
            "bob bob bob bob bob",
            "bob bob bob bob bob bob bob",
            "152 152 152 152 152 152",
        ] {
            let key = Signature::from_passphrase(phrase);
            assert!(
                key.is_err(),
                "invalid phrase {phrase:?} decoded into key {key:?}"
            );
        }

        Ok(())
    }
}
