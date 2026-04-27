use pulldown_cmark::{html, Options, Parser};

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
