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
