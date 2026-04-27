use toml_edit::DocumentMut;

#[test]
fn toml_edit_parses_and_mutates_document() {
    let mut doc: DocumentMut = "title = 'demo'\n[server]\nport = 8080\n".parse().unwrap();
    doc["server"]["host"] = toml_edit::value("127.0.0.1");
    let rendered = doc.to_string();

    assert!(rendered.contains("host"));
    assert!(rendered.contains("127.0.0.1"));
}

#[test]
fn toml_edit_roundtrips_nested_mutations() {
    let mut doc: DocumentMut = "[package]\nname = 'demo'\n[features]\ndefault = ['a']\n"
        .parse()
        .unwrap();
    doc["package"]["version"] = toml_edit::value("0.1.0");
    doc["features"]["extra"] = toml_edit::value(toml_edit::Array::from_iter(["b", "c"]));
    let rendered = doc.to_string();
    let reparsed: DocumentMut = rendered.parse().unwrap();

    assert_eq!(reparsed["package"]["name"].as_str(), Some("demo"));
    assert_eq!(reparsed["package"]["version"].as_str(), Some("0.1.0"));
}
