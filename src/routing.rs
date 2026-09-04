//! Typed route declarations shared by router construction and security-policy tests.
//!
//! A route is registered only through [`declare_routes!`]. The macro emits both
//! the Axum `Router::route` calls and an immutable [`RouteSpec`] inventory from
//! the same declaration, so adding a handler without classifying its security
//! contract is a compile-time-visible change.

use std::fmt::{self, Display, Formatter};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteSurface {
    Web,
    ApiV2,
    Setup,
}

impl Display for RouteSurface {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Web => "web",
            Self::ApiV2 => "api-v2",
            Self::Setup => "setup",
        })
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl Display for RouteMethod {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthContract {
    Public,
    Session,
    AdminSession,
    MonitoringCredential,
    ShareCapability,
    SetupToken,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MfaContract {
    None,
    VerifiedSession,
    MutationContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CsrfContract {
    None,
    FormField,
    JsonField,
    Header,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditContract {
    None,
    Observation,
    Required,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BodyContract {
    None,
    Form,
    Json,
    Multipart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MutationContract {
    ReadOnly,
    Authentication,
    Preference,
    Privileged,
    Storage,
    Upload,
    ShareUnlock,
    Setup,
}

/// Security and protocol contract for one explicitly registered HTTP method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteSpec {
    pub surface: RouteSurface,
    pub method: RouteMethod,
    pub path: &'static str,
    pub auth: AuthContract,
    pub mfa: MfaContract,
    pub csrf: CsrfContract,
    pub audit: AuditContract,
    pub body: BodyContract,
    pub mutation: MutationContract,
}

impl RouteSpec {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        surface: RouteSurface,
        method: RouteMethod,
        path: &'static str,
        auth: AuthContract,
        mfa: MfaContract,
        csrf: CsrfContract,
        audit: AuditContract,
        body: BodyContract,
        mutation: MutationContract,
    ) -> Self {
        Self {
            surface,
            method,
            path,
            auth,
            mfa,
            csrf,
            audit,
            body,
            mutation,
        }
    }

    pub fn externally_visible_path(&self) -> String {
        match self.surface {
            RouteSurface::ApiV2 => format!("/api/v2{}", self.path),
            RouteSurface::Web | RouteSurface::Setup => self.path.to_owned(),
        }
    }
}

/// Declares an Axum route table and its typed security inventory together.
///
/// Each method must state all contracts. Optional `layers [...]` apply to the
/// complete path-level `MethodRouter` in the listed order.
#[macro_export]
macro_rules! declare_routes {
    (
        $spec_vis:vis static $spec_name:ident = $surface:ident;
        $fn_vis:vis fn $fn_name:ident($router:ident : $router_ty:ty) -> $return_ty:ty;
        $(
            $path:literal {
                $(
                    $method:ident => $handler:path,
                    [$auth:ident, $mfa:ident, $csrf:ident, $audit:ident, $body:ident, $mutation:ident];
                )+
            }
            $(layers [$($layer:expr),+ $(,)?];)?
        )+
    ) => {
        $spec_vis static $spec_name: &[$crate::routing::RouteSpec] = &[
            $(
                $(
                    $crate::routing::RouteSpec::new(
                        $crate::routing::RouteSurface::$surface,
                        $crate::declare_routes!(@method $method),
                        $path,
                        $crate::routing::AuthContract::$auth,
                        $crate::routing::MfaContract::$mfa,
                        $crate::routing::CsrfContract::$csrf,
                        $crate::routing::AuditContract::$audit,
                        $crate::routing::BodyContract::$body,
                        $crate::routing::MutationContract::$mutation,
                    ),
                )+
            )+
        ];

        $fn_vis fn $fn_name($router: $router_ty) -> $return_ty {
            let router = $router;
            $(
                let methods = axum::routing::MethodRouter::new();
                $(
                    let methods = $crate::declare_routes!(@install methods, $method, $handler);
                )+
                $(
                    let methods = methods$(.layer($layer))+;
                )?
                let router = router.route($path, methods);
            )+
            router
        }
    };

    (@method GET) => { $crate::routing::RouteMethod::Get };
    (@method HEAD) => { $crate::routing::RouteMethod::Head };
    (@method POST) => { $crate::routing::RouteMethod::Post };
    (@method PUT) => { $crate::routing::RouteMethod::Put };
    (@method PATCH) => { $crate::routing::RouteMethod::Patch };
    (@method DELETE) => { $crate::routing::RouteMethod::Delete };

    (@install $methods:ident, GET, $handler:path) => { $methods.get($handler) };
    (@install $methods:ident, HEAD, $handler:path) => { $methods.head($handler) };
    (@install $methods:ident, POST, $handler:path) => { $methods.post($handler) };
    (@install $methods:ident, PUT, $handler:path) => { $methods.put($handler) };
    (@install $methods:ident, PATCH, $handler:path) => { $methods.patch($handler) };
    (@install $methods:ident, DELETE, $handler:path) => { $methods.delete($handler) };
}
