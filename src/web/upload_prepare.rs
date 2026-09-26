use askama::Template;
use axum::response::Html;
use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct UploadPrepareForm {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Template)]
#[template(path = "web/upload_prepare.html")]
pub(super) struct PreparedUploadTemplate {
    pub action: String,
    pub path: String,
    pub csrf: String,
    pub upload_id: String,
    pub allow_overwrite: bool,
    pub back_link: String,
}

impl PreparedUploadTemplate {
    pub(super) fn render_page(&self) -> super::Result<Html<String>> {
        Ok(Html(super::templates::public_page(
            crate::i18n::UPLOAD_FILE,
            self,
        )?))
    }
}
