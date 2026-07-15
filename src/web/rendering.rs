use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
};

use axum::{
    extract::{Form, State},
    http::{header, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
};
use base64::Engine as _;
use serde::Deserialize;

use super::{human, internal, AppError, Result};
use crate::{
    http_auth::runtime_settings,
    i18n::{self, Locale, MessageKey},
    AppState,
};

pub(super) fn esc(s: &str) -> String {
    let mut escaped = String::with_capacity(
        escaped_html_len(s).expect("an existing string has a representable escaped length"),
    );
    for character in s.chars() {
        push_html_escaped(&mut escaped, character);
    }
    escaped
}

pub(super) fn push_html_escaped(escaped: &mut String, character: char) {
    match character {
        '&' => escaped.push_str("&amp;"),
        '<' => escaped.push_str("&lt;"),
        '>' => escaped.push_str("&gt;"),
        '"' => escaped.push_str("&quot;"),
        '\'' => escaped.push_str("&#39;"),
        character => escaped.push(character),
    }
}

pub(super) fn escaped_html_len(value: &str) -> Option<usize> {
    value.chars().try_fold(0usize, |length, character| {
        length.checked_add(match character {
            '&' => 5,
            '<' | '>' => 4,
            '"' => 6,
            '\'' => 5,
            character => character.len_utf8(),
        })
    })
}

pub(super) async fn stylesheet_asset() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        crate::ui::STYLESHEET,
    )
}

pub(super) async fn app_js() -> impl IntoResponse {
    let script = format!(
        "{}\n{}",
        r#"document.addEventListener('click',async e=>{const closer=e.target.closest('[data-details-close]');if(closer){closer.closest('details')?.removeAttribute('open');return;}const b=e.target.closest('[data-copy]');if(!b)return;try{await navigator.clipboard.writeText(b.dataset.copy);b.textContent='<vl-i18n key="common.copied"/>';}catch(_){b.textContent='<vl-i18n key="common.copy_failed"/>';}});
const pad=n=>String(n).padStart(2,'0');
function fillSelect(select,from,to,current){select.innerHTML='';for(let i=from;i<=to;i++){const o=document.createElement('option');o.value=String(i);o.textContent=String(i).padStart(select.dataset.pad||0,'0');if(i===current)o.selected=true;select.appendChild(o);}}
function daysInMonth(y,m){return new Date(y,m,0).getDate();}
function initDateTimePicker(picker){const input=picker.querySelector('[data-datetime-input]');const pop=picker.querySelector('[data-datetime-popover]');const toggle=picker.querySelector('[data-datetime-toggle]');const year=picker.querySelector('[data-dt-year]');const month=picker.querySelector('[data-dt-month]');const day=picker.querySelector('[data-dt-day]');const hour=picker.querySelector('[data-dt-hour]');const minute=picker.querySelector('[data-dt-minute]');const now=new Date();fillSelect(year,now.getFullYear(),now.getFullYear()+5,now.getFullYear());fillSelect(month,1,12,now.getMonth()+1);fillSelect(hour,0,23,23);fillSelect(minute,0,59,0);function syncDays(){const selected=Number(day.value)||now.getDate();fillSelect(day,1,daysInMonth(Number(year.value),Number(month.value)),Math.min(selected,daysInMonth(Number(year.value),Number(month.value))))}function setOpen(open){pop.hidden=!open;toggle.setAttribute('aria-expanded',String(open));if(open)year.focus();}syncDays();[year,month].forEach(s=>s.addEventListener('change',syncDays));toggle.addEventListener('click',()=>setOpen(pop.hidden));picker.addEventListener('keydown',e=>{if(e.key==='Escape'){setOpen(false);toggle.focus();}});picker.querySelector('[data-datetime-apply]').addEventListener('click',()=>{const date=document.documentElement.lang==='de'?`${pad(day.value)}.${pad(month.value)}.${year.value}`:`${year.value}-${pad(month.value)}-${pad(day.value)}`;input.value=`${date} ${pad(hour.value)}:${pad(minute.value)}`;setOpen(false);});picker.querySelector('[data-datetime-clear]').addEventListener('click',()=>{input.value='';setOpen(false);});}
function initDeleteConfirmation(form){const input=form.querySelector('[data-confirm-input]');const button=form.querySelector('[data-confirm-delete]');if(!input||!button)return;const sync=()=>{button.disabled=input.value!==form.dataset.requiredName;};input.addEventListener('input',sync);sync();input.focus();}
document.addEventListener('click',e=>{document.querySelectorAll('[data-datetime-picker]').forEach(p=>{if(!p.contains(e.target)){const pop=p.querySelector('[data-datetime-popover]');const toggle=p.querySelector('[data-datetime-toggle]');if(pop)pop.hidden=true;if(toggle)toggle.setAttribute('aria-expanded','false');}});});
function initFileSelection(){const bar=document.querySelector('[data-selection-bar]');const link=bar?.querySelector('[data-selection-share]');const name=bar?.querySelector('[data-selection-name]');if(!bar||!link||!name)return;document.querySelectorAll('[data-file-select]').forEach(input=>input.addEventListener('change',()=>{if(!input.checked)return;name.textContent=`${input.value||'/'} <vl-i18n key="files.selected"/>`;link.href=`/admin/shares/new?path=${encodeURIComponent(input.value)}`;bar.hidden=false;}));}
function initShareReview(){const form=document.querySelector('[data-share-create]');if(!form)return;const review=form.parentElement.querySelector('[data-share-review]');const passwordToggle=form.querySelector('[data-password-toggle]');const passwordFields=form.querySelector('[data-password-fields]');const uploadRules=form.querySelector('[data-upload-rules]');const permissionLabels={download_only:'<vl-i18n key="share.download_only"/>',upload_only:'<vl-i18n key="share.upload_only"/>',download_upload:'<vl-i18n key="share.download_upload"/>'};const sync=()=>{const permission=form.querySelector('[name="permission"]:checked')?.value||form.querySelector('[name="permission"]')?.value||'download_only';const alias=form.elements.alias?.value.trim();const maximum=form.elements.max_downloads?.value.trim();const protectedShare=Boolean(passwordToggle?.checked);if(review){review.querySelector('[data-review-permission]').textContent=permissionLabels[permission]||permission;review.querySelector('[data-review-password]').textContent=protectedShare?'<vl-i18n key="share.password_protected"/>':'<vl-i18n key="share.no_password"/>';review.querySelector('[data-review-limit]').textContent=maximum?`${maximum} <vl-i18n key="share.transfers"/>`:'<vl-i18n key="common.unlimited"/>';const url=review.querySelector('[data-review-url]');if(url){const base=url.textContent.split('/v/')[0].split('/s/')[0];url.textContent=alias?`${base}/s/${alias}`:`${base}/v/••••••••`;}}if(passwordFields){passwordFields.hidden=!protectedShare;passwordFields.querySelectorAll('input').forEach(input=>{input.disabled=!protectedShare;input.required=protectedShare;});}if(uploadRules)uploadRules.hidden=permission==='download_only';};form.addEventListener('input',sync);form.addEventListener('change',sync);sync();}
function webauthnBuffer(value){const padded=value.replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((value.length+3)%4);const raw=atob(padded);return Uint8Array.from(raw,c=>c.charCodeAt(0));}
function webauthnBase64(value){const bytes=new Uint8Array(value);let raw='';bytes.forEach(byte=>raw+=String.fromCharCode(byte));return btoa(raw).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function webauthnOptions(options){options.publicKey.challenge=webauthnBuffer(options.publicKey.challenge);if(options.publicKey.user)options.publicKey.user.id=webauthnBuffer(options.publicKey.user.id);for(const key of ['allowCredentials','excludeCredentials'])for(const item of options.publicKey[key]||[])item.id=webauthnBuffer(item.id);return options;}
function webauthnCredential(credential){const response={};for(const key of ['attestationObject','clientDataJSON','authenticatorData','signature','userHandle'])if(credential.response[key])response[key]=webauthnBase64(credential.response[key]);if(credential.response.getTransports)response.transports=credential.response.getTransports();return{id:credential.id,rawId:webauthnBase64(credential.rawId),type:credential.type,response,clientExtensionResults:credential.getClientExtensionResults(),authenticatorAttachment:credential.authenticatorAttachment};}
async function webauthnPost(url,body){const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});if(!response.ok)throw new Error(await response.text());return response.json();}
function initSecurityKeyLogin(){const button=document.querySelector('[data-security-key-login]');if(!button)return;const status=document.querySelector('[data-security-key-status]');const csrf=button.dataset.csrf;button.addEventListener('click',async()=>{button.disabled=true;status.textContent='<vl-i18n key="auth.security_key_wait"/>';try{const options=webauthnOptions(await webauthnPost('/mfa/security-key/start',{csrf}));const credential=await navigator.credentials.get(options);const result=await webauthnPost('/mfa/security-key/finish',{csrf,credential:webauthnCredential(credential)});location.assign(result.redirect);}catch(error){status.textContent='<vl-i18n key="auth.security_key_failed"/>';button.disabled=false;}});}
function initSecurityKeyRegistration(){const form=document.querySelector('[data-security-key-register]');if(!form)return;const status=form.querySelector('[data-security-key-status]');form.addEventListener('submit',async event=>{event.preventDefault();const button=form.querySelector('button');button.disabled=true;status.textContent='<vl-i18n key="auth.security_key_wait"/>';const label=form.elements.label.value.trim();try{const options=webauthnOptions(await webauthnPost('/admin/account/security-keys/register/start',{csrf:form.dataset.csrf,current_password:form.elements.current_password.value,label}));const credential=await navigator.credentials.create(options);const result=await webauthnPost('/admin/account/security-keys/register/finish',{csrf:form.dataset.csrf,label,credential:webauthnCredential(credential)});location.assign(result.redirect);}catch(error){status.textContent='<vl-i18n key="auth.security_key_failed"/>';button.disabled=false;}});}
document.addEventListener('DOMContentLoaded',()=>{document.querySelectorAll('[data-datetime-picker]').forEach(initDateTimePicker);document.querySelectorAll('[data-delete-confirmation]').forEach(initDeleteConfirmation);initFileSelection();initShareReview();initSecurityKeyLogin();initSecurityKeyRegistration();});
document.addEventListener('submit',e=>{e.target.querySelectorAll('[data-tz-offset]').forEach(i=>{i.value=String(new Date().getTimezoneOffset())})});"#,
        crate::ui::UPLOAD_QUEUE_JAVASCRIPT
    );
    let script = i18n::render_markers(i18n::current_locale(), &script);
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        script,
    )
}

pub(super) const MB: u64 = 1_000_000;
pub(super) const GB: u64 = 1_000_000_000;
pub(super) const STORAGE_RESERVE_BYTES: u64 = 64 * MB;

pub(super) async fn logo_svg() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        LOGO_SVG,
    )
}

pub(super) async fn favicon_svg() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        LOGO_SVG,
    )
}

pub(super) async fn favicon_png() -> impl IntoResponse {
    const PNG_32X32_BASE64: &str = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAJYSURBVFhH7ZZPaBNBFMZzFDwUBD0IYr0IIi2Ih4ho6ElysFAotUUsPQiBBrzUglcppIdSaSG99FKKgoEWhGLpQbGEFkXBEggihKTaokhJMNA/YG5Pvl1edjJvs5ndLHrJ4UeYtzPvffO9mc1GTp25TP+TiB7413QEBBbQ1X2Tekdm6c7UJ+sXY32OCb4FXLz1kGKT63Q/QwLE8Vxf44WRAN7twMJPUdQNzDN1xVOA125NaeVKUwHXRtMiWTsgn14jsIAnG0SZnEPqnZyjE4qAiXWivd9Ex38kiM9tycKhCXj6lqh8JAvrpN/L4qEI+HrgFNks2W1A/NEa0WqeqHpiP8MvnApVwEzWKf6mIJMD2G/NqRF9+C6ftyVg7YsjYPyVTM4UK81b4VsAXiS8GLvmxGMrduzuswLdfvy6DsZoC7cCcJsCCTh7JV5fjKvGSdEOxFC0O5aogzHiarvgHOe4EH0gangKAP3zu9Zi2M5JcROwMzcHuFixbM/F1cR4cLEichsJUM+B6sJ+tbG/Ojs/7HkQgvGN5EuR20iA2gaQLclW6OAK8jn4uG/HmtnfUgDgNgC0gpOjFforGMXZfhbpZb+RAPU2gOefnQJsMyxn25n8L3t+NLEscvoSAPDVo4pQz4Mb29/s6wr3Tp/rEfl8C8CHBaxUReAVjGuGnaMdAO8L/kMaWjq0zpCeS8dIADh//R4Nv6g1iPDiUl9S5HDDWAC4OpgShdxo1XcVXwIADmUzJxDHc32NF74FAPQ2Pp1rKI6xSc91AglgsFscNr+7VmlLQBh0BPwFr0PNxBrwyt4AAAAASUVORK5CYII=";
    static PNG_32X32: OnceLock<Vec<u8>> = OnceLock::new();
    let png = PNG_32X32.get_or_init(|| {
        base64::engine::general_purpose::STANDARD
            .decode(PNG_32X32_BASE64)
            .expect("embedded 32x32 favicon must be valid base64")
    });
    ([(header::CONTENT_TYPE, "image/png")], png.as_slice())
}

pub(super) const LOGO_SVG: &str = crate::ui::LOGO_SVG;

#[derive(Deserialize)]
pub(super) struct LocaleForm {
    locale: String,
    return_to: String,
}

pub(super) fn safe_internal_return_to(value: &str) -> String {
    if !value.starts_with('/') || value.starts_with("//") || value.contains('\\') {
        return "/".to_string();
    }
    let Ok(uri) = value.parse::<Uri>() else {
        return "/".to_string();
    };
    if uri.scheme().is_some() || uri.authority().is_some() || uri.path() == "/locale" {
        return "/".to_string();
    }
    uri.path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
}

pub(super) async fn set_locale(
    State(state): State<AppState>,
    Form(form): Form<LocaleForm>,
) -> Result<Response> {
    let locale = Locale::parse(&form.locale)
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Ungültige Sprache"))?;
    let return_to = safe_internal_return_to(&form.return_to);
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000;{}",
        i18n::LOCALE_COOKIE,
        locale.code(),
        if state.config.security.secure_cookie {
            " Secure;"
        } else {
            ""
        }
    );
    let mut response = Redirect::to(&return_to).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(internal)?,
    );
    Ok(response)
}

pub(super) fn locale_switcher() -> String {
    let locale = i18n::current_locale();
    let label = i18n::text(locale, i18n::LANGUAGE);
    let return_to = i18n::current_return_to();
    format!(
        r#"<form class="vl-locale-switch" method="post" action="/locale" aria-label="{}"><input type="hidden" name="return_to" value="{}"><button class="vl-locale-switch__option" name="locale" value="de" type="submit"{}>DE</button><span aria-hidden="true">/</span><button class="vl-locale-switch__option" name="locale" value="en" type="submit"{}>EN</button></form>"#,
        esc(label),
        esc(&return_to),
        if locale == Locale::De {
            r#" aria-current="true""#
        } else {
            ""
        },
        if locale == Locale::En {
            r#" aria-current="true""#
        } else {
            ""
        },
    )
}

pub(super) fn plain_page(title: &str, body: &str) -> String {
    let locale = i18n::current_locale();
    let title = i18n::text_from_german(locale, title);
    let body = i18n::render_markers(locale, body);
    format!(
        r##"<!doctype html><html lang="{}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{} · VaultLink</title><link rel="icon" href="/assets/favicon.svg" type="image/svg+xml"><link rel="alternate icon" href="/assets/favicon-32.png" type="image/png"><link rel="stylesheet" href="/assets/vaultlink.css"><script src="/assets/app.js" defer></script></head><body class="vl-ui"><a class="vl-skip-link" href="#main-content">{}</a><div class="vl-public-shell"><header class="vl-public-header">{}{}</header><main id="main-content" class="vl-public-main">{}</main></div></body></html>"##,
        locale.code(),
        esc(&title),
        i18n::text(locale, i18n::SKIP_TO_CONTENT),
        crate::ui::brand_lockup(i18n::text(locale, i18n::BRAND_TAGLINE)),
        locale_switcher(),
        body
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NavSection {
    Files,
    Links,
    Admins,
    Settings,
    Audit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PageId {
    Account,
    Files,
    Preview,
    DeleteConfirm,
    Links,
    CreateLink,
    Admins,
    AdminCreated,
    MfaReset,
    Settings,
    AuditSecurity,
}

impl PageId {
    const fn title(self) -> MessageKey {
        match self {
            Self::Account => i18n::ACCOUNT,
            Self::Files => i18n::NAV_FILES,
            Self::Preview => i18n::TITLE_PREVIEW,
            Self::DeleteConfirm => i18n::TITLE_DELETE_CONFIRM,
            Self::Links => i18n::NAV_LINKS,
            Self::CreateLink => i18n::CREATE_LINK,
            Self::Admins => i18n::NAV_ADMINS,
            Self::AdminCreated => i18n::TITLE_ADMIN_CREATED,
            Self::MfaReset => i18n::TITLE_MFA_RESET,
            Self::Settings => i18n::NAV_SETTINGS,
            Self::AuditSecurity => i18n::TITLE_AUDIT_SECURITY,
        }
    }

    const fn nav(self) -> Option<NavSection> {
        match self {
            Self::Account => None,
            Self::Files | Self::Preview | Self::DeleteConfirm => Some(NavSection::Files),
            Self::Links | Self::CreateLink => Some(NavSection::Links),
            Self::Admins | Self::AdminCreated | Self::MfaReset => Some(NavSection::Admins),
            Self::Settings => Some(NavSection::Settings),
            Self::AuditSecurity => Some(NavSection::Audit),
        }
    }
}

pub(super) fn admin_page(
    state: &AppState,
    page: PageId,
    body: &str,
    show_create_link: bool,
    csrf_token: &str,
) -> String {
    admin_page_with_locale_switcher(state, page, body, show_create_link, csrf_token, true)
}

pub(super) fn admin_page_without_locale_switcher(
    state: &AppState,
    page: PageId,
    body: &str,
    show_create_link: bool,
    csrf_token: &str,
) -> String {
    admin_page_with_locale_switcher(state, page, body, show_create_link, csrf_token, false)
}

pub(super) fn admin_page_with_locale_switcher(
    state: &AppState,
    page: PageId,
    body: &str,
    show_create_link: bool,
    csrf_token: &str,
    show_locale_switcher: bool,
) -> String {
    let locale = i18n::current_locale();
    let title = i18n::text(locale, page.title());
    let create_link = if show_create_link {
        format!(
            r#"<a class="vl-button" href="/admin/shares/new">{} {}</a>"#,
            crate::ui::icon(crate::ui::Icon::Link),
            i18n::text(locale, i18n::CREATE_LINK),
        )
    } else {
        String::new()
    };
    let active = page.nav();
    let nav = [
        crate::ui::nav_link(
            "/admin",
            i18n::text(locale, i18n::NAV_FILES),
            crate::ui::Icon::Folder,
            active == Some(NavSection::Files),
        ),
        crate::ui::nav_link(
            "/admin/shares",
            i18n::text(locale, i18n::NAV_LINKS),
            crate::ui::Icon::Link,
            active == Some(NavSection::Links),
        ),
        crate::ui::nav_link(
            "/admin/admins",
            i18n::text(locale, i18n::NAV_ADMINS),
            crate::ui::Icon::Users,
            active == Some(NavSection::Admins),
        ),
        crate::ui::nav_link(
            "/admin/settings",
            i18n::text(locale, i18n::NAV_SETTINGS),
            crate::ui::Icon::Settings,
            active == Some(NavSection::Settings),
        ),
        crate::ui::nav_link(
            "/admin/audit",
            i18n::text(locale, i18n::NAV_AUDIT),
            crate::ui::Icon::Audit,
            active == Some(NavSection::Audit),
        ),
    ]
    .join("");
    let body = i18n::render_markers(locale, body);
    let system_panel = i18n::render_markers(locale, &system_panel(state));
    let locale_switcher = if show_locale_switcher {
        locale_switcher()
    } else {
        String::new()
    };
    format!(
        r##"<!doctype html><html lang="{}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{} · VaultLink</title><link rel="icon" href="/assets/favicon.svg" type="image/svg+xml"><link rel="alternate icon" href="/assets/favicon-32.png" type="image/png"><link rel="stylesheet" href="/assets/vaultlink.css"><script src="/assets/app.js" defer></script></head><body class="vl-ui"><a class="vl-skip-link" href="#main-content">{}</a><div class="vl-app-shell"><aside class="vl-sidebar">{}<nav class="vl-nav" aria-label="{}">{}</nav><div class="vl-system-card"><strong><span aria-hidden="true">●</span> {}</strong><span>{}</span></div></aside><div class="vl-content"><header class="vl-topbar"><div><p class="vl-eyebrow">{}</p><h1>{}</h1></div><div class="vl-topbar-actions">{}{}<a class="vl-button vl-button--ghost" href="/admin/account">{} {}</a><form method="post" action="/logout"><input type="hidden" name="csrf" value="{}"><button class="vl-button vl-button--secondary">{} {}</button></form></div></header><main id="main-content" class="vl-main">{}</main></div></div></body></html>"##,
        locale.code(),
        esc(title),
        i18n::text(locale, i18n::SKIP_TO_CONTENT),
        crate::ui::brand_lockup(i18n::text(locale, i18n::BRAND_TAGLINE)),
        i18n::text(locale, i18n::MAIN_NAVIGATION),
        nav,
        i18n::text(locale, i18n::VAULTLINK_AVAILABLE),
        system_panel,
        i18n::text(locale, i18n::VAULTLINK_ADMIN),
        esc(title),
        create_link,
        locale_switcher,
        crate::ui::icon(crate::ui::Icon::User),
        i18n::text(locale, i18n::ACCOUNT_LINK),
        esc(csrf_token),
        crate::ui::icon(crate::ui::Icon::Logout),
        i18n::text(locale, i18n::LOG_OUT),
        body
    )
}

pub(super) fn system_panel(state: &AppState) -> String {
    let disk = disk_stats(state.secure_root.display_root())
        .map(|d| {
            format!(
                r#"<vl-i18n key="audit.storage"/>: {} <vl-i18n key="common.free"/> / {}"#,
                human(d.free),
                human(d.total)
            )
        })
        .unwrap_or_else(|| r#"<vl-i18n key="audit.storage"/>: n/a"#.to_string());
    format!(
        "{}<br>URL: {}<br><vl-i18n key=\"audit.server_mode\"/>: {:?}",
        disk,
        esc(&runtime_settings(state).public_base_url),
        state.config.server.mode
    )
}

pub(super) struct DiskStats {
    pub(super) free: u64,
    pub(super) total: u64,
}

pub(super) fn disk_stats(path: &Path) -> Option<DiskStats> {
    disk_stats_linux(path)
}

pub(super) fn disk_stats_linux(path: &Path) -> Option<DiskStats> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let stat = rustix::fs::statvfs(&canonical).ok()?;
    let block_size = stat.f_bsize;
    Some(DiskStats {
        free: stat.f_bavail.saturating_mul(block_size),
        total: stat.f_blocks.saturating_mul(block_size),
    })
}

pub(super) fn storage_has_room(path: &Path, needed: u64) -> bool {
    disk_stats(path).is_none_or(|stats| {
        stats
            .free
            .saturating_sub(STORAGE_RESERVE_BYTES)
            .saturating_sub(needed)
            > 0
    })
}

pub(super) static UPLOAD_BYTES_RESERVED: AtomicU64 = AtomicU64::new(0);

pub(super) struct UploadChunkReservation {
    bytes: u64,
}

impl UploadChunkReservation {
    pub(super) fn acquire(path: &Path, bytes: u64) -> Option<Self> {
        loop {
            let reserved = UPLOAD_BYTES_RESERVED.load(Ordering::Acquire);
            if disk_stats(path).is_some_and(|stats| {
                stats
                    .free
                    .saturating_sub(STORAGE_RESERVE_BYTES)
                    .saturating_sub(reserved)
                    <= bytes
            }) {
                return None;
            }
            if UPLOAD_BYTES_RESERVED
                .compare_exchange_weak(
                    reserved,
                    reserved.checked_add(bytes)?,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(Self { bytes });
            }
        }
    }
}

impl Drop for UploadChunkReservation {
    fn drop(&mut self) {
        UPLOAD_BYTES_RESERVED.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

pub(super) fn storage_full_error(error: &std::io::Error) -> bool {
    const ENOSPC: i32 = 28;
    const EDQUOT: i32 = 122;
    error.kind() == std::io::ErrorKind::StorageFull
        || matches!(error.raw_os_error(), Some(ENOSPC | EDQUOT | 112))
}
