//! Shared, build-free UI primitives for VaultLink's server-rendered pages.
//!
//! The stylesheet and SVGs are compiled into the binary. HTML helpers escape
//! every caller-provided value; route-specific markup remains in the owning
//! module so security-sensitive forms stay explicit.

/// Shared VaultLink stylesheet served by the application as `/assets/vaultlink.css`.
///
/// All component selectors are scoped below `.vl-ui` and all custom properties
/// use the `--vl-` prefix so screens can migrate incrementally without changing
/// legacy pages.
pub const STYLESHEET: &str = include_str!("../assets/web/vaultlink.css");

/// Progressive enhancement for single-request upload forms.
///
/// The server-rendered form deliberately remains a single-file fallback. This
/// module enables multiple selection only after all queue controls were found
/// and initialized, then submits exactly one file part per request.
pub const UPLOAD_QUEUE_JAVASCRIPT: &str = include_str!("../assets/web/upload-queue.js");

/// Standalone VaultLink file/shield mark shared by every rendered surface.
pub const LOGO_SVG: &str = include_str!("../assets/branding/vaultlink-logo.svg");
pub const FAVICON_PNG: &[u8] = include_bytes!("../assets/branding/favicon-32.png");

/// Icons available to server-rendered UI helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icon {
    ArrowLeft,
    Audit,
    Calendar,
    Check,
    ChevronDown,
    Copy,
    Download,
    File,
    Folder,
    Link,
    Lock,
    Logout,
    More,
    Search,
    Server,
    Settings,
    Shield,
    Trash,
    Upload,
    User,
    Users,
    Warning,
}

impl Icon {
    fn paths(self) -> &'static str {
        match self {
            Self::ArrowLeft => r#"<path d="m15 18-6-6 6-6"/><path d="M9 12h10"/>"#,
            Self::Audit => {
                r#"<path d="M12 3 4.5 6v5.5c0 4.7 2.8 8 7.5 9.5 4.7-1.5 7.5-4.8 7.5-9.5V6L12 3Z"/><path d="m9.2 12 1.8 1.8 4-4"/>"#
            }
            Self::Calendar => {
                r#"<rect x="3.5" y="5.5" width="17" height="15" rx="2"/><path d="M8 3v5M16 3v5M3.5 10h17"/>"#
            }
            Self::Check => r#"<path d="m5 12.5 4.2 4.2L19 7"/>"#,
            Self::ChevronDown => r#"<path d="m7 9.5 5 5 5-5"/>"#,
            Self::Copy => {
                r#"<rect x="8" y="8" width="11" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h2"/>"#
            }
            Self::Download => r#"<path d="M12 3v12M7.5 10.5 12 15l4.5-4.5"/><path d="M4 20h16"/>"#,
            Self::File => r#"<path d="M6 3.5h8l4 4V21H6Z"/><path d="M14 3.5V8h4"/>"#,
            Self::Folder => r#"<path d="M3.5 6.5h6l2 2h9v10.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2Z"/>"#,
            Self::Link => {
                r#"<path d="m9.5 14.5-1 1a4 4 0 1 1-5.7-5.7l3-3a4 4 0 0 1 5.7 0"/><path d="m14.5 9.5 1-1a4 4 0 1 1 5.7 5.7l-3 3a4 4 0 0 1-5.7 0"/><path d="m8.5 15.5 7-7"/>"#
            }
            Self::Lock => {
                r#"<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>"#
            }
            Self::Logout => {
                r#"<path d="M10 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h5"/><path d="m15 8 4 4-4 4M19 12H9"/>"#
            }
            Self::More => {
                r#"<circle cx="5" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r="1" fill="currentColor" stroke="none"/>"#
            }
            Self::Search => r#"<circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 5 5"/>"#,
            Self::Server => {
                r#"<rect x="4" y="4" width="16" height="6" rx="2"/><rect x="4" y="14" width="16" height="6" rx="2"/><path d="M8 7h.01M8 17h.01M12 7h5M12 17h5"/>"#
            }
            Self::Settings => {
                r#"<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/>"#
            }
            Self::Shield => {
                r#"<path d="M12 3 4.5 6v5.5c0 4.7 2.8 8 7.5 9.5 4.7-1.5 7.5-4.8 7.5-9.5V6L12 3Z"/>"#
            }
            Self::Trash => r#"<path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6"/>"#,
            Self::Upload => r#"<path d="M12 16V4M7.5 8.5 12 4l4.5 4.5"/><path d="M4 20h16"/>"#,
            Self::User => r#"<circle cx="12" cy="8" r="4"/><path d="M4.5 21a7.5 7.5 0 0 1 15 0"/>"#,
            Self::Users => {
                r#"<circle cx="9" cy="8" r="3"/><path d="M3.5 20v-2a5.5 5.5 0 0 1 11 0v2M16 5.5a3 3 0 0 1 0 5.8M17 14a5 5 0 0 1 3.5 4.8V20"/>"#
            }
            Self::Warning => {
                r#"<path d="M10.3 4.5 2.8 18a2 2 0 0 0 1.8 3h14.8a2 2 0 0 0 1.8-3L13.7 4.5a2 2 0 0 0-3.4 0Z"/><path d="M12 9v5M12 18h.01"/>"#
            }
        }
    }
}

/// Render a decorative, non-focusable inline icon from a closed set of paths.
pub fn icon(icon: Icon) -> String {
    format!(
        r#"<svg class="vl-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{}</svg>"#,
        icon.paths()
    )
}

/// Render the shared brand lockup. The mark is decorative because the visible
/// product name immediately follows it.
pub fn brand_lockup(subtitle: &str) -> String {
    format!(
        r#"<div class="vl-brand"><span class="vl-brand__mark" aria-hidden="true">{LOGO_SVG}</span><span class="vl-brand__copy">VaultLink<small>{}</small></span></div>"#,
        escape_html(subtitle)
    )
}

/// Semantic badge variants with fixed class names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BadgeTone {
    Neutral,
    Success,
    Warning,
    Danger,
}

impl BadgeTone {
    fn class(self) -> &'static str {
        match self {
            Self::Neutral => "vl-badge",
            Self::Success => "vl-badge vl-badge--success",
            Self::Warning => "vl-badge vl-badge--warning",
            Self::Danger => "vl-badge vl-badge--danger",
        }
    }
}

/// Render an escaped status badge.
pub fn badge(tone: BadgeTone, text: &str) -> String {
    format!(
        r#"<span class="{}">{}</span>"#,
        tone.class(),
        escape_html(text)
    )
}

/// Render an escaped internal navigation link with a typed icon.
pub fn nav_link(href: &str, label: &str, icon_name: Icon, current: bool) -> String {
    let current = if current {
        r#" aria-current="page""#
    } else {
        ""
    };
    format!(
        r#"<a class="vl-nav-link" href="{}"{}>{}<span>{}</span></a>"#,
        escape_html(href),
        current,
        icon(icon_name),
        escape_html(label)
    )
}

/// Escape text for HTML text and quoted attribute contexts.
pub fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stylesheet_contains_shared_breakpoints_and_accessibility_guards() {
        for breakpoint in ["75rem", "60rem", "45rem", "30rem"] {
            assert!(STYLESHEET.contains(breakpoint));
        }
        assert!(STYLESHEET.contains(":focus-visible"));
        assert!(STYLESHEET.contains("--vl-control-height: 2.75rem"));
        assert!(STYLESHEET.contains("background-attachment: fixed"));
        assert!(STYLESHEET.contains("prefers-reduced-motion"));
        assert!(STYLESHEET.contains(".vl-nav-link:hover"));
        assert!(STYLESHEET.contains(".vl-nav-link[aria-current=\"page\"]"));
    }

    #[test]
    fn helpers_escape_all_caller_provided_copy() {
        let brand = brand_lockup(r#"<script>alert("x")</script>"#);
        assert!(!brand.contains("<script>"));
        assert!(brand.contains("&lt;script&gt;"));

        let nav = nav_link(r#"/admin?x="bad""#, "<Dateien>", Icon::Folder, true);
        assert!(nav.contains(r#"aria-current="page""#));
        assert!(nav.contains("&quot;bad&quot;"));
        assert!(nav.contains("&lt;Dateien&gt;"));
    }

    #[test]
    fn shared_brand_assets_use_the_background_free_file_shield() {
        assert!(LOGO_SVG.contains("vl-file-front"));
        assert!(LOGO_SVG.contains("vl-file-back"));
        assert!(LOGO_SVG.contains(r##"fill="#081226""##));
        assert!(!LOGO_SVG.contains("<rect"));
        assert_eq!(&FAVICON_PNG[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn typed_icons_are_decorative_and_badges_are_escaped() {
        let folder = icon(Icon::Folder);
        assert!(folder.contains(r#"aria-hidden="true""#));
        assert!(folder.contains(r#"focusable="false""#));
        assert!(!folder.contains("<script"));

        let status = badge(BadgeTone::Danger, "<unsafe>");
        assert!(status.contains("vl-badge--danger"));
        assert!(status.contains("&lt;unsafe&gt;"));
    }
}
