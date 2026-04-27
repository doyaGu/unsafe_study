use memchr::memmem;

fn naive_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn memchr_handles_unaligned_public_inputs() {
    let owned = b"Xheader:value\r\nfoo bar foo baz foo\0tail".to_vec();
    let haystack = &owned[1..owned.len() - 1];

    assert_eq!(
        memchr::memchr(b':', haystack),
        haystack.iter().position(|&b| b == b':')
    );
    assert_eq!(
        memchr::memrchr(b'o', haystack),
        haystack.iter().rposition(|&b| b == b'o')
    );
    assert_eq!(
        memchr::memchr2(b'\r', b'\n', haystack),
        haystack.iter().position(|&b| b == b'\r' || b == b'\n')
    );
    assert_eq!(
        memchr::memchr3(b'f', b'b', b'z', haystack),
        haystack
            .iter()
            .position(|&b| b == b'f' || b == b'b' || b == b'z')
    );

    let finder = memmem::Finder::new(b"foo");
    assert_eq!(finder.find(haystack), naive_find(haystack, b"foo"));
    assert_eq!(
        memmem::rfind(haystack, b"foo"),
        haystack.windows(3).rposition(|w| w == b"foo")
    );
}

#[test]
fn memchr_memmem_handles_edge_needles() {
    let haystack = b"\0foofoo\0barbazfoo";

    assert_eq!(memmem::find(haystack, b""), Some(0));
    assert_eq!(memmem::find(haystack, b"foo"), Some(1));
    assert_eq!(memmem::rfind(haystack, b"foo"), Some(14));

    let finder = memmem::Finder::new(b"bar");
    assert_eq!(finder.find(haystack), Some(8));
}
