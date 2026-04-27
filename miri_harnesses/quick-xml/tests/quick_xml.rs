use quick_xml::events::Event;
use quick_xml::Reader;

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
