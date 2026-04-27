use roxmltree::Document;

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
