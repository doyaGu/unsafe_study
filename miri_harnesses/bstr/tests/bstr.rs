use bstr::ByteSlice;

#[test]
fn bstr_ascii_boundary_offsets() {
    let owned = b"Xascii only line\nsecond line\xfftail".to_vec();
    let slice = &owned[1..owned.len() - 1];

    assert_eq!(slice.find_byte(b'\n'), Some(15));
    assert!(slice.lines().count() >= 2);
    assert!(slice.fields().count() >= 4);
    assert!(slice.to_str().is_err());
}

#[test]
fn bstr_invalid_utf8_search_and_trim() {
    let owned = b" \talpha\xffbeta  ".to_vec();
    let slice = &owned[1..owned.len() - 1];

    assert_eq!(slice.trim_start().as_bytes(), b"alpha\xffbeta ");
    assert_eq!(slice.trim_end().as_bytes(), b"\talpha\xffbeta");
    assert_eq!(slice.find("beta"), Some(7));
    assert_eq!(slice.rfind_byte(b'a'), Some(10));
}

#[test]
fn bstr_grapheme_iteration_and_reverse_search() {
    let text = "a\u{0300}\u{0316} 🇺🇸 z";
    let bytes = text.as_bytes();
    let graphemes: Vec<_> = bytes.graphemes().collect();
    let grapheme_indices: Vec<_> = bytes.grapheme_indices().collect();

    assert!(graphemes.len() >= 3);
    assert_eq!(graphemes.len(), grapheme_indices.len());
    assert_eq!(bytes.rfind("z"), Some(text.len() - 1));
}
