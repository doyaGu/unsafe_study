use serde_json::{Deserializer, Value};

#[test]
fn serde_json_streams_multiple_values() {
    let mut stream = Deserializer::from_str(r#"{"x":1} {"x":2} [3,4]"#).into_iter::<Value>();

    assert_eq!(stream.next().unwrap().unwrap()["x"], 1);
    assert_eq!(stream.next().unwrap().unwrap()["x"], 2);
    assert_eq!(stream.next().unwrap().unwrap()[0], 3);
    assert!(stream.next().is_none());
}

#[test]
fn serde_json_handles_escape_and_number_edges() {
    let cases = [
        br#"{"text":"line\nbreak","value":-0.0,"exp":1e-9}"#.as_slice(),
        br#"["\uD83D\uDE00",18446744073709551615,-9223372036854775808]"#.as_slice(),
        br#"{"nested":{"arr":[0,1,2,3],"unicode":"\u2603"}}"#.as_slice(),
    ];

    for input in cases {
        let parsed = serde_json::from_slice::<Value>(input);
        assert!(parsed.is_ok(), "failed to parse {:?}", input);
    }
}
