use goblin::Object;
use pulldown_cmark::{html, Options, Parser};
use quick_xml::events::Event;
use quick_xml::Reader;
use roxmltree::Document;
use simd_json::{prelude::ValueObjectAccess, BorrowedValue};
use toml_edit::DocumentMut;

#[test]
fn simd_json_parses_mutable_input() {
    let mut input = br#"{"outer":{"answer":42},"items":[1,2,3],"text":"hi"}"#.to_vec();
    let value: BorrowedValue = simd_json::to_borrowed_value(&mut input).unwrap();

    assert!(value.get("outer").is_some());
    assert!(value.get("items").is_some());
}

#[test]
fn quick_xml_streams_events() {
    let xml = r#"<?xml version="1.0"?><root><item k="v">text</item><empty/></root>"#;
    let mut reader = Reader::from_str(xml);
    let mut start_count = 0usize;
    let mut text_count = 0usize;

    loop {
        match reader.read_event().unwrap() {
            Event::Start(_) | Event::Empty(_) => start_count += 1,
            Event::Text(_) => text_count += 1,
            Event::Eof => break,
            _ => {}
        }
    }

    assert!(start_count >= 3);
    assert!(text_count >= 1);
}

#[test]
fn goblin_parses_minimal_object_bytes() {
    let mut elf = [0u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16] = 2;
    elf[18] = 62;
    elf[52] = 64;

    let _ = Object::parse(&elf);
}

#[test]
fn toml_edit_parses_and_mutates_document() {
    let mut doc: DocumentMut = "title = 'demo'\n[server]\nport = 8080\n".parse().unwrap();
    doc["server"]["host"] = toml_edit::value("127.0.0.1");
    let rendered = doc.to_string();

    assert!(rendered.contains("host"));
    assert!(rendered.contains("127.0.0.1"));
}

#[test]
fn pulldown_cmark_renders_html() {
    let markdown = "# Heading\n\n- a\n- b\n\n`code`\n";
    let parser = Parser::new_ext(markdown, Options::all());
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);

    assert!(html_output.contains("<h1>Heading</h1>"));
    assert!(html_output.contains("<li>a</li>"));
    assert!(html_output.contains("<code>code</code>"));
}

#[test]
fn roxmltree_builds_tree() {
    let doc = Document::parse(r#"<root><item id="1"/><item id="2">text</item></root>"#).unwrap();
    let root = doc.root_element();
    let items: Vec<_> = root.children().filter(|n| n.is_element()).collect();

    assert_eq!(root.tag_name().name(), "root");
    assert_eq!(items.len(), 2);
}
