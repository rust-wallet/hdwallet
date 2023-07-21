use super::ENGLISH_WORD;

pub fn word_list() -> Vec<String> {
    format!("{}", ENGLISH_WORD)
        .lines()
        .map(|word| -> String { String::from(word) })
        .collect::<Vec<String>>()
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;

    use crate::wordslist::words_list::word_list;

    #[test]
    fn it_split_words() {
        let ww = word_list();
        assert_eq!(ww.len(), 2048)
    }
}
