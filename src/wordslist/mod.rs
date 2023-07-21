use lazy_static_include::lazy_static_include_str;

pub mod words_list;
lazy_static_include_str! {
    ENGLISH_WORD=>"assets/english.txt"
}
