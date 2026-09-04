use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

include!("config/model.rs");
include!("config/defaults.rs");
include!("config/validation.rs");
include!("config/tls.rs");

#[cfg(test)]
include!("config/tests.rs");
