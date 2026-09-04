use askama::Template;

use super::{
    common::{encoded, parent_path},
    TEXT_PREVIEW_RENDER_UNIT_BYTES,
};

#[derive(Template)]
#[template(path = "web/public/text_preview.html")]
pub(super) struct PublicTextPreviewTemplate<'a> {
    pub(super) back_link: &'a str,
    pub(super) download_link: &'a str,
}

#[derive(Template)]
#[template(path = "web/public/preview_too_large.html")]
struct PublicPreviewTooLargeTemplate {
    back_link: String,
    download_link: String,
    path: String,
    message: String,
    size: String,
}

#[derive(Template)]
#[template(path = "web/public/media_preview.html")]
struct PublicMediaPreviewTemplate {
    back_link: String,
    download_link: String,
    size: String,
    raw_url: String,
    image: bool,
}

pub(super) fn public_back_link(
    public_route: &str,
    share_relative_file: &str,
    is_directory_share: bool,
) -> String {
    if !is_directory_share {
        return public_route.to_string();
    }
    let parent = parent_path(share_relative_file).unwrap_or_default();
    if parent.is_empty() {
        public_route.to_string()
    } else {
        format!("{public_route}?path={}", encoded(&parent))
    }
}

pub(super) fn text_preview_render_permits(max_preview_size: u64) -> u32 {
    max_preview_size
        .div_ceil(TEXT_PREVIEW_RENDER_UNIT_BYTES)
        .clamp(1, crate::TEXT_PREVIEW_RENDER_BUDGET_PERMITS as u64) as u32
}

#[path = "public_preview/page.rs"]
mod page_adapter;
#[path = "public_preview/raw.rs"]
mod raw_adapter;

pub(crate) use page_adapter::public_preview;
pub(crate) use raw_adapter::public_preview_raw;
