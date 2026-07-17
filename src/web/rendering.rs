use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use super::{common::internal, AppError, Result};
use crate::{
    i18n::{self, Locale, MessageKey},
    AppState,
};

#[cfg(test)]
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

pub(super) const ASSET_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default, Deserialize)]
pub(super) struct AssetQuery {
    pub(super) v: Option<String>,
    pub(super) lang: Option<String>,
}

fn asset_cache_control(query: &AssetQuery, locale_bound: bool) -> HeaderValue {
    let version_matches = query.v.as_deref() == Some(ASSET_VERSION);
    let locale_matches = !locale_bound || matches!(query.lang.as_deref(), Some("de") | Some("en"));
    if version_matches && locale_matches {
        HeaderValue::from_static("public, max-age=31536000, immutable")
    } else {
        HeaderValue::from_static("no-store")
    }
}

pub(super) async fn stylesheet_asset(Query(query): Query<AssetQuery>) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, asset_cache_control(&query, false)),
        ],
        crate::ui::STYLESHEET,
    )
        .into_response()
}

pub(super) async fn app_js(Query(query): Query<AssetQuery>) -> Response {
    static SCRIPTS: OnceLock<[String; 2]> = OnceLock::new();
    let scripts = SCRIPTS.get_or_init(|| {
        let source = format!(
        "{}\n{}",
        r#"function closeActionDetails(except){document.querySelectorAll('.vl-action-details[open]').forEach(details=>{if(details!==except)details.removeAttribute('open');});}
document.addEventListener('click',async e=>{const closer=e.target.closest('[data-details-close]');if(closer){closer.closest('details')?.removeAttribute('open');return;}const action=e.target.closest('.vl-action-details');const summary=e.target.closest('.vl-action-details > summary');closeActionDetails(summary?.parentElement||action);const b=e.target.closest('[data-copy]');if(!b)return;try{await navigator.clipboard.writeText(b.dataset.copy);b.textContent='<vl-i18n key="common.copied"/>';}catch(_){b.textContent='<vl-i18n key="common.copy_failed"/>';}});
document.addEventListener('keydown',e=>{if(e.key!=='Escape')return;const open=[...document.querySelectorAll('.vl-action-details[open]')];if(open.length===0)return;e.preventDefault();const summary=open.at(-1).querySelector(':scope > summary');closeActionDetails();summary?.focus();});
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
async function webauthnPost(url,body){const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});if(!response.ok){const error=new Error('VaultLink WebAuthn request failed');error.name='VaultLinkHttpError';error.status=response.status;throw error;}return response.json();}
function ensureWebauthnAvailable(){if(!window.isSecureContext){const error=new Error('WebAuthn requires a secure context');error.name='SecurityError';throw error;}if(!window.PublicKeyCredential||!navigator.credentials){const error=new Error('WebAuthn is unavailable');error.name='NotSupportedError';throw error;}}
function webauthnFailureMessage(error){const name=error&&typeof error.name==='string'?error.name:'';if(name==='VaultLinkHttpError')return `<vl-i18n key="auth.security_key_server_error"/> (HTTP ${error.status||'?'})`;const messages={NotAllowedError:'<vl-i18n key="auth.security_key_not_allowed"/>',SecurityError:'<vl-i18n key="auth.security_key_security_error"/>',NotSupportedError:'<vl-i18n key="auth.security_key_not_supported"/>',InvalidStateError:'<vl-i18n key="auth.security_key_invalid_state"/>',AbortError:'<vl-i18n key="auth.security_key_not_allowed"/>'};const message=messages[name]||'<vl-i18n key="auth.security_key_failed"/>';return name?`${message} [${name}]`:message;}
function initSecurityKeyLogin(){const button=document.querySelector('[data-security-key-login]');if(!button)return;const status=document.querySelector('[data-security-key-status]');const csrf=button.dataset.csrf;button.addEventListener('click',async()=>{button.disabled=true;status.textContent='<vl-i18n key="auth.security_key_wait"/>';try{ensureWebauthnAvailable();const options=webauthnOptions(await webauthnPost('/mfa/security-key/start',{csrf}));const credential=await navigator.credentials.get(options);const result=await webauthnPost('/mfa/security-key/finish',{csrf,credential:webauthnCredential(credential)});location.assign(result.redirect);}catch(error){status.textContent=webauthnFailureMessage(error);button.disabled=false;}});}
function initSecurityKeyRegistration(){const form=document.querySelector('[data-security-key-register]');if(!form)return;const status=form.querySelector('[data-security-key-status]');form.addEventListener('submit',async event=>{event.preventDefault();const button=form.querySelector('button');button.disabled=true;status.textContent='<vl-i18n key="auth.security_key_wait"/>';const label=form.elements.label.value.trim();try{ensureWebauthnAvailable();const options=webauthnOptions(await webauthnPost('/admin/account/security-keys/register/start',{csrf:form.dataset.csrf,current_password:form.elements.current_password.value,label}));const credential=await navigator.credentials.create(options);const result=await webauthnPost('/admin/account/security-keys/register/finish',{csrf:form.dataset.csrf,label,credential:webauthnCredential(credential)});location.assign(result.redirect);}catch(error){status.textContent=webauthnFailureMessage(error);button.disabled=false;}});}
function initFieldInfoTooltips(){const triggers=[...document.querySelectorAll('.vl-field-info')];if(triggers.length===0)return;const position=trigger=>{const tooltip=trigger.querySelector('.vl-field-tooltip');if(!tooltip)return;const triggerRect=trigger.getBoundingClientRect();const tooltipRect=tooltip.getBoundingClientRect();const margin=16;const halfWidth=tooltipRect.width/2;const left=Math.max(margin+halfWidth,Math.min(window.innerWidth-margin-halfWidth,triggerRect.left+triggerRect.width/2));let top=triggerRect.bottom+8;if(top+tooltipRect.height>window.innerHeight-margin&&triggerRect.top-tooltipRect.height-8>=margin)top=triggerRect.top-tooltipRect.height-8;tooltip.style.setProperty('--vl-tooltip-left',`${left}px`);tooltip.style.setProperty('--vl-tooltip-top',`${top}px`);};const close=except=>{for(const trigger of triggers){if(trigger===except)continue;trigger.classList.remove('is-open');trigger.setAttribute('aria-expanded','false');}};for(const trigger of triggers){trigger.setAttribute('aria-expanded','false');trigger.addEventListener('pointerenter',()=>position(trigger));trigger.addEventListener('focus',()=>position(trigger));trigger.addEventListener('click',event=>{event.preventDefault();event.stopPropagation();position(trigger);const open=!trigger.classList.contains('is-open');close(trigger);trigger.classList.toggle('is-open',open);trigger.setAttribute('aria-expanded',String(open));trigger.focus();});trigger.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();trigger.click();}else if(event.key==='Escape'){trigger.classList.remove('is-open');trigger.setAttribute('aria-expanded','false');trigger.blur();}});trigger.addEventListener('blur',()=>{trigger.classList.remove('is-open');trigger.setAttribute('aria-expanded','false');});}document.addEventListener('click',()=>close());window.addEventListener('resize',()=>triggers.filter(trigger=>trigger.matches(':hover, :focus')||trigger.classList.contains('is-open')).forEach(position));window.addEventListener('scroll',()=>triggers.filter(trigger=>trigger.matches(':hover, :focus')||trigger.classList.contains('is-open')).forEach(position),true);}
function initLocalTimes(){const locale=document.documentElement.lang||undefined;const formatter=new Intl.DateTimeFormat(locale,{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});document.querySelectorAll('time[data-local-time]').forEach(time=>{const date=new Date(time.dateTime);if(!Number.isNaN(date.getTime()))time.textContent=formatter.format(date);});}
document.addEventListener('DOMContentLoaded',()=>{document.querySelectorAll('[data-datetime-picker]').forEach(initDateTimePicker);document.querySelectorAll('[data-delete-confirmation]').forEach(initDeleteConfirmation);initFileSelection();initShareReview();initSecurityKeyLogin();initSecurityKeyRegistration();initFieldInfoTooltips();initLocalTimes();});
document.addEventListener('submit',e=>{e.target.querySelectorAll('[data-tz-offset]').forEach(i=>{i.value=String(new Date().getTimezoneOffset())})});"#,
        crate::ui::UPLOAD_QUEUE_JAVASCRIPT
    );
        [
            i18n::render_markers(Locale::De, &source),
            i18n::render_markers(Locale::En, &source),
        ]
    });
    let locale = match query.lang.as_deref() {
        Some("de") => Locale::De,
        Some("en") => Locale::En,
        _ => i18n::current_locale(),
    };
    let script = match locale {
        Locale::De => &scripts[0],
        Locale::En => &scripts[1],
    };
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/javascript; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, asset_cache_control(&query, true)),
        ],
        script.as_str(),
    )
        .into_response()
}

pub(super) const MB: u64 = 1_000_000;
pub(super) const GB: u64 = 1_000_000_000;
pub(super) const STORAGE_RESERVE_BYTES: u64 = 64 * MB;

pub(super) async fn logo_svg(Query(query): Query<AssetQuery>) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, asset_cache_control(&query, false)),
        ],
        LOGO_SVG,
    )
        .into_response()
}

pub(super) async fn favicon_svg(Query(query): Query<AssetQuery>) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, asset_cache_control(&query, false)),
        ],
        LOGO_SVG,
    )
        .into_response()
}

pub(super) async fn favicon_png(Query(query): Query<AssetQuery>) -> Response {
    let mut response = crate::ui::FAVICON_PNG.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, asset_cache_control(&query, false));
    response
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
    headers: HeaderMap,
    Form(form): Form<LocaleForm>,
) -> Result<Response> {
    let expected = url::Url::parse(&state.config.server.public_base_url).map_err(internal)?;
    let supplied = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| url::Url::parse(value).ok());
    if supplied.as_ref().map(url::Url::origin) != Some(expected.origin()) {
        return Err(AppError(
            StatusCode::FORBIDDEN,
            "Cross-site locale change rejected",
        ));
    }
    let locale =
        Locale::parse(&form.locale).ok_or(AppError(StatusCode::BAD_REQUEST, "Invalid language"))?;
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
    pub(super) const fn title(self) -> MessageKey {
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

    pub(super) const fn nav(self) -> Option<NavSection> {
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

pub(super) async fn storage_has_room(state: &AppState, needed: u64) -> std::io::Result<bool> {
    state
        .disk_stats_cache
        .get(state.secure_root.display_root())
        .await
        .map(|stats| {
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

pub(super) enum StorageReservationError {
    CapacityUnavailable,
    InsufficientStorage,
}

impl UploadChunkReservation {
    pub(super) async fn acquire(
        state: &AppState,
        bytes: u64,
    ) -> std::result::Result<Self, StorageReservationError> {
        let stats = state
            .disk_stats_cache
            .get(state.secure_root.display_root())
            .await
            .map_err(|_| StorageReservationError::CapacityUnavailable)?;
        loop {
            let reserved = UPLOAD_BYTES_RESERVED.load(Ordering::Acquire);
            if stats
                .free
                .saturating_sub(STORAGE_RESERVE_BYTES)
                .saturating_sub(reserved)
                <= bytes
            {
                return Err(StorageReservationError::InsufficientStorage);
            }
            let next = reserved
                .checked_add(bytes)
                .ok_or(StorageReservationError::InsufficientStorage)?;
            if UPLOAD_BYTES_RESERVED
                .compare_exchange_weak(reserved, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(Self { bytes });
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
