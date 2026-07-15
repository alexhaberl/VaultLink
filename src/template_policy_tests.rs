use std::{fs, path::Path};

fn visit_templates(path: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(path).expect("template directory must be readable") {
        let path = entry.expect("template entry must be readable").path();
        if path.is_dir() {
            visit_templates(&path, files);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "html")
        {
            files.push(path);
        }
    }
}

#[test]
fn templates_follow_the_html_security_policy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut files = Vec::new();
    visit_templates(&root, &mut files);
    assert!(
        !files.is_empty(),
        "the template policy must cover templates"
    );

    let mut stream_markers = 0;
    let mut has_alert = false;
    let mut has_polite_status = false;
    for path in files {
        let source = fs::read_to_string(&path).expect("template must be UTF-8");
        let lower = source.to_ascii_lowercase();
        has_alert |= lower.contains("role=\"alert\"");
        has_polite_status |=
            lower.contains("role=\"status\"") && lower.contains("aria-live=\"polite\"");
        assert!(
            !lower.contains("style="),
            "inline style in {}",
            path.display()
        );
        for handler in ["onclick=", "onchange=", "oninput=", "onsubmit=", "onload="] {
            assert!(
                !lower.contains(handler),
                "event handler in {}",
                path.display()
            );
        }
        for (index, _) in lower.match_indices("<script") {
            let rest = &lower[index..];
            let end = rest.find('>').map_or(rest.len(), |end| end + 1);
            let tag = &rest[..end];
            assert!(tag.contains(" src="), "inline script in {}", path.display());
        }
        for expression in source.match_indices("|safe") {
            let start = source[..expression.0].rfind("{{").unwrap_or(expression.0);
            let context = &source[start..expression.0];
            assert!(
                context.contains("icon") || context.contains("qr") || context.contains("brand"),
                "unauthorized safe filter in {}: {}",
                path.display(),
                context
            );
        }
        stream_markers += source
            .matches("<!--VAULTLINK_ESCAPED_TEXT_PREVIEW_STREAM-->")
            .count();
    }
    assert_eq!(
        stream_markers, 2,
        "one marker is required in each text-preview shell"
    );
    assert!(has_alert, "error notices must expose an alert role");
    assert!(
        has_polite_status,
        "asynchronous upload and WebAuthn feedback must expose a polite status region"
    );
}
