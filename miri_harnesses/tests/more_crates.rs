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
fn quick_xml_handles_attributes_and_namespaces() {
    let xml = r#"<root xmlns:h="urn:test"><h:item id="1" flag="yes">value</h:item></root>"#;
    let mut reader = Reader::from_str(xml);
    let mut item_attrs = 0usize;

    loop {
        match reader.read_event().unwrap() {
            Event::Start(start) if start.name().as_ref().ends_with(b"item") => {
                item_attrs = start.attributes().count();
            }
            Event::Eof => break,
            _ => {}
        }
    }

    assert_eq!(item_attrs, 2);
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
fn goblin_parses_minimal_pe_bytes() {
    let mut pe = vec![0u8; 0x100];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c] = 0x40;
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    pe[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes());
    pe[0x58..0x5a].copy_from_slice(&0x20Bu16.to_le_bytes());

    let _ = Object::parse(&pe);
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
fn pulldown_cmark_renders_nested_structures() {
    let markdown = "> quote\n\n| a | b |\n| - | - |\n| 1 | 2 |\n\n- [x] done";
    let parser = Parser::new_ext(markdown, Options::all());
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);

    assert!(html_output.contains("<blockquote>"));
    assert!(html_output.contains("<table>"));
    assert!(html_output.contains("checkbox"));
}

#[test]
fn roxmltree_builds_tree() {
    let doc = Document::parse(r#"<root><item id="1"/><item id="2">text</item></root>"#).unwrap();
    let root = doc.root_element();
    let items: Vec<_> = root.children().filter(|n| n.is_element()).collect();

    assert_eq!(root.tag_name().name(), "root");
    assert_eq!(items.len(), 2);
}

#[test]
fn roxmltree_handles_namespaces_and_text() {
    let doc = Document::parse(
        r#"<root xmlns:h="urn:test"><h:item id="1">text</h:item><item>more</item></root>"#,
    )
    .unwrap();
    let root = doc.root_element();
    let items: Vec<_> = root.children().filter(|n| n.is_element()).collect();

    assert_eq!(items.len(), 2);
    assert_eq!(items[0].tag_name().namespace(), Some("urn:test"));
    assert_eq!(items[0].text(), Some("text"));
}
