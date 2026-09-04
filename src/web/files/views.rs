#[derive(Template)]
#[template(path = "web/files/text_preview.html")]
struct AdminTextPreviewTemplate<'a> {
    parent_path: &'a str,
    relative_path: &'a str,
}

#[derive(Template)]
#[template(path = "web/files/delete_confirm.html")]
struct DeleteFileConfirmTemplate {
    heading: String,
    path: String,
    name: String,
    affected_shares: usize,
    csrf_token: String,
    confirmation_required: bool,
    parent_path: String,
}

struct AdminBreadcrumbView {
    label: String,
    url: String,
}

struct AdminSortHeaderView {
    label_key: &'static str,
    aria_sort: &'static str,
    indicator: &'static str,
    sort: &'static str,
    direction: &'static str,
}

struct AdminFileRowView {
    path: String,
    name: String,
    icon: super::templates::TrustedMarkup,
    is_directory: bool,
    type_label: &'static str,
    size: String,
    modified_datetime: Option<String>,
    modified_label: String,
    open_url: Option<String>,
    preview_url: Option<String>,
    share_url: String,
    download_url: Option<String>,
    delete_url: String,
}

#[derive(Template)]
#[template(path = "web/files/browser.html")]
struct AdminBrowserTemplate {
    notice_key: Option<&'static str>,
    notice_success: bool,
    used_storage: String,
    free_storage: String,
    active_links: usize,
    breadcrumbs: Vec<AdminBreadcrumbView>,
    path: String,
    path_encoded: String,
    up_url: Option<String>,
    csrf_token: String,
    replacements_allowed: bool,
    upload_icon: super::templates::TrustedMarkup,
    folder_icon: super::templates::TrustedMarkup,
    more_icon: super::templates::TrustedMarkup,
    trash_icon: super::templates::TrustedMarkup,
    current_folder_target: String,
    sort: &'static str,
    direction: &'static str,
    search: String,
    search_encoded: Option<String>,
    headers: Vec<AdminSortHeaderView>,
    rows: Vec<AdminFileRowView>,
    truncated: bool,
    previous_cursor: Option<String>,
    next_cursor: Option<String>,
}

#[derive(Template)]
#[template(path = "web/files/preview_too_large.html")]
struct AdminPreviewTooLargeTemplate {
    parent_path: String,
    path: String,
    message: String,
    size: String,
}

#[derive(Template)]
#[template(path = "web/files/media_preview.html")]
struct AdminMediaPreviewTemplate {
    parent_path: String,
    path: String,
    size: String,
    raw_url: String,
    image: bool,
}

fn admin_file_time(value: std::time::SystemTime) -> (String, String) {
    let utc = DateTime::<Utc>::from(value);
    (
        utc.to_rfc3339_opts(SecondsFormat::Secs, true),
        super::common::format_utc_minute(utc),
    )
}

fn admin_breadcrumb_views(path: &str) -> Vec<AdminBreadcrumbView> {
    let mut current = String::new();
    path.trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .map(|part| {
            current = join_display(&current, part);
            AdminBreadcrumbView {
                label: part.to_string(),
                url: format!("/admin?path={}", encoded(&current)),
            }
        })
        .collect()
}

fn admin_sort_header_view(
    label_key: &'static str,
    column: super::common::FileSortColumn,
    current_column: super::common::FileSortColumn,
    current_direction: super::common::FileSortDirection,
) -> AdminSortHeaderView {
    use super::common::FileSortDirection;
    let active = column == current_column;
    let next_direction = if active && current_direction == FileSortDirection::Ascending {
        FileSortDirection::Descending
    } else {
        FileSortDirection::Ascending
    };
    AdminSortHeaderView {
        label_key,
        aria_sort: if active {
            match current_direction {
                FileSortDirection::Ascending => "ascending",
                FileSortDirection::Descending => "descending",
            }
        } else {
            "none"
        },
        indicator: if active {
            match current_direction {
                FileSortDirection::Ascending => "↑",
                FileSortDirection::Descending => "↓",
            }
        } else {
            ""
        },
        sort: file_sort_column_value(column),
        direction: file_sort_direction_value(next_direction),
    }
}

fn admin_file_row_view(
    path: &str,
    name: String,
    is_directory: bool,
    size: u64,
    modified: Option<std::time::SystemTime>,
    settings: &crate::runtime::RuntimeSettings,
) -> AdminFileRowView {
    let target = encoded(path);
    let modified = modified.map(admin_file_time);
    let (modified_datetime, modified_label) = if let Some((datetime, label)) = modified {
        (Some(datetime), label)
    } else {
        (None, "—".into())
    };
    AdminFileRowView {
        path: path.to_string(),
        name,
        icon: super::templates::TrustedMarkup::static_icon(if is_directory {
            crate::ui::Icon::Folder
        } else {
            crate::ui::Icon::File
        }),
        is_directory,
        type_label: i18n::text(
            i18n::current_locale(),
            if is_directory {
                i18n::FOLDER
            } else {
                i18n::FILE
            },
        ),
        size: if is_directory {
            "—".into()
        } else {
            human(size)
        },
        modified_datetime,
        modified_label,
        open_url: is_directory.then(|| format!("/admin?path={target}")),
        preview_url: (!is_directory && preview_allowed(path, settings))
            .then(|| format!("/admin/preview?path={target}")),
        share_url: format!("/admin/shares/new?path={target}"),
        download_url: (!is_directory).then(|| format!("/admin/files/download?path={target}")),
        delete_url: format!("/admin/files/delete?path={target}"),
    }
}
