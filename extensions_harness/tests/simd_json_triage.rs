use simd_json::{
    prelude::{ValueAsArray, ValueAsScalar, ValueObjectAccess},
    BorrowedValue, OwnedValue,
};

#[test]
fn simd_json_borrowed_value_parses_object_with_strings() {
    let mut input = br#"{"outer":{"answer":42},"items":[1,2,3],"text":"hi"}"#.to_vec();
    let value: BorrowedValue = simd_json::to_borrowed_value(&mut input).unwrap();

    assert!(value.get("outer").is_some());
    assert!(value.get("items").is_some());
    assert_eq!(value.get("text").unwrap().as_str(), Some("hi"));
}

#[test]
fn simd_json_owned_value_parses_object_with_strings() {
    let mut input = br#"{"outer":{"answer":42},"items":[1,2,3],"text":"hi"}"#.to_vec();
    let value: OwnedValue = simd_json::to_owned_value(&mut input).unwrap();

    assert!(value.get("outer").is_some());
    assert!(value.get("items").is_some());
    assert_eq!(value.get("text").unwrap().as_str(), Some("hi"));
}

#[test]
fn simd_json_tape_builds_and_exposes_root_value() {
    let mut input = br#"{"outer":{"answer":42},"items":[1,2,3],"text":"hi"}"#.to_vec();
    let tape = simd_json::to_tape(&mut input).unwrap();
    let value = tape.as_value();

    assert!(value.get("outer").is_some());
    assert!(value.get("items").is_some());
    assert_eq!(value.get("text").unwrap().as_str(), Some("hi"));
}

#[test]
fn simd_json_lazy_upgrade_from_tape_preserves_fields() {
    let mut input = br#"{"outer":{"answer":42},"items":[1,2,3],"text":"hi"}"#.to_vec();
    let tape = simd_json::to_tape(&mut input).unwrap();
    let lazy = simd_json::value::lazy::Value::from_tape(tape.as_value());
    let value = lazy.into_value();

    assert!(value.get("outer").is_some());
    assert!(value.get("items").is_some());
    assert_eq!(value.get("text").unwrap().as_str(), Some("hi"));
}

#[test]
fn simd_json_borrowed_value_parses_numeric_array() {
    let mut input = br#"[1,2,3]"#.to_vec();
    let value: BorrowedValue = simd_json::to_borrowed_value(&mut input).unwrap();

    assert_eq!(value.as_array().unwrap().len(), 3);
}

#[test]
fn simd_json_tape_exposes_numeric_array() {
    let mut input = br#"[1,2,3]"#.to_vec();
    let tape = simd_json::to_tape(&mut input).unwrap();
    let value = tape.as_value();

    assert_eq!(value.as_array().unwrap().len(), 3);
}

#[test]
fn simd_json_borrowed_value_handles_unaligned_input_offset() {
    let mut owned = br#"X{"outer":{"answer":42},"items":[1,2,3],"text":"hi"}Y"#.to_vec();
    let end = owned.len() - 1;
    let value: BorrowedValue = simd_json::to_borrowed_value(&mut owned[1..end]).unwrap();

    assert!(value.get("outer").is_some());
    assert_eq!(value.get("text").unwrap().as_str(), Some("hi"));
}

#[test]
fn simd_json_borrowed_value_parses_number_heavy_document() {
    let mut input =
        br#"{"ints":[12345678,87654321,1844674407370955161],"floats":[1.25,2.5e10,-3.125e-4]}"#
            .to_vec();
    let value: BorrowedValue = simd_json::to_borrowed_value(&mut input).unwrap();
    let ints = value.get("ints").unwrap().as_array().unwrap();
    let floats = value.get("floats").unwrap().as_array().unwrap();

    assert_eq!(ints.len(), 3);
    assert_eq!(floats.len(), 3);
}

#[test]
fn simd_json_owned_value_parses_escape_heavy_strings() {
    let mut input =
        br#"{"text":"line\nbreak\tindent","emoji":"\uD83D\uDE00","path":"C:\\tmp\\file.json"}"#
            .to_vec();
    let value: OwnedValue = simd_json::to_owned_value(&mut input).unwrap();

    assert_eq!(
        value.get("text").unwrap().as_str(),
        Some("line\nbreak\tindent")
    );
    assert_eq!(value.get("emoji").unwrap().as_str(), Some("😀"));
    assert_eq!(
        value.get("path").unwrap().as_str(),
        Some("C:\\tmp\\file.json")
    );
}
