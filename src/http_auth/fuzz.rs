//! Offline grammar and ambiguity checks for the production credential selector.

use super::*;

fn selected(headers: &HeaderMap, name: &str) -> std::result::Result<u8, StatusCode> {
    monitoring_credentials(headers, name)
        .map(|credentials| match credentials {
            MonitoringCredentials::Session => 1,
            MonitoringCredentials::ServiceToken(_) => 2,
        })
        .map_err(|error| error.status)
}

fn check_arbitrary_headers(input: &[u8], name: &str) {
    let mut headers = HeaderMap::new();
    // Records are [kind, byte length, value...]. HeaderValue rejects bytes the
    // HTTP stack cannot represent; non-ASCII field values still reach to_str.
    let mut records = input;
    for _ in 0..16 {
        if records.len() < 2 {
            break;
        }
        let key = if records[0] & 1 == 0 {
            header::COOKIE
        } else {
            header::AUTHORIZATION
        };
        let length = usize::from(records[1]).min(records.len() - 2);
        if let Ok(value) = HeaderValue::from_bytes(&records[2..2 + length]) {
            headers.append(key, value);
        }
        records = &records[2 + length..];
    }
    if let Ok(credentials) = monitoring_credentials(&headers, name) {
        match credentials {
            MonitoringCredentials::Session => {
                assert!(named_cookie(&headers, name).is_some());
                assert_eq!(headers.get_all(header::AUTHORIZATION).iter().count(), 0);
            }
            MonitoringCredentials::ServiceToken(token) => {
                assert!(named_cookie(&headers, name).is_none());
                assert_eq!(headers.get_all(header::AUTHORIZATION).iter().count(), 1);
                assert!(token.starts_with(SERVICE_TOKEN_PREFIX));
                let encoded = &token[SERVICE_TOKEN_PREFIX.len()..];
                assert_eq!(encoded.len(), 43);
                let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
                assert_eq!(decoded.len(), 32);
                assert_eq!(URL_SAFE_NO_PAD.encode(decoded), encoded);
            }
        }
    }
    // Reordering complete headers cannot turn ambiguous input into accepted
    // credentials. Compare acceptance; diagnostic priority need not be stable.
    let mut reversed = HeaderMap::new();
    for key in [header::COOKIE, header::AUTHORIZATION] {
        let values: Vec<_> = headers.get_all(&key).iter().cloned().collect();
        for value in values.into_iter().rev() {
            reversed.append(key.clone(), value);
        }
    }
    assert_eq!(
        selected(&headers, name).ok(),
        selected(&reversed, name).ok()
    );
}

fn check_token_canonicality(token: &str, name: &str) {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    let inactive_cookie = if name == SESSION_COOKIE {
        SECURE_SESSION_COOKIE
    } else {
        SESSION_COOKIE
    };
    headers.insert(
        header::COOKIE,
        format!("unrelated=value; {inactive_cookie}=other")
            .parse()
            .unwrap(),
    );
    assert_eq!(
        selected(&headers, name),
        Ok(2),
        "unrelated cookies do not change token selection"
    );

    // A 32-byte token leaves two unused bits in its final Base64 character.
    // Toggle one of those bits while keeping length, alphabet and decoded data
    // unchanged: accepting the alternate spelling would violate canonicality.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut noncanonical = token.as_bytes().to_vec();
    let last = noncanonical.last_mut().unwrap();
    let index = ALPHABET.iter().position(|value| value == last).unwrap();
    assert_eq!(index & 3, 0);
    *last = ALPHABET[index | 1];
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", String::from_utf8(noncanonical).unwrap())
            .parse()
            .unwrap(),
    );
    assert_eq!(selected(&headers, name), Err(StatusCode::UNAUTHORIZED));
}

pub fn check_auth_headers(input: &[u8]) {
    let name = if input.first().copied().unwrap_or(0) & 1 == 0 {
        SESSION_COOKIE
    } else {
        SECURE_SESSION_COOKIE
    };
    check_arbitrary_headers(input.get(1..).unwrap_or_default(), name);
    let mut token_bytes = [0u8; 32];
    for (destination, source) in token_bytes.iter_mut().zip(input.iter().copied()) {
        *destination = source;
    }
    let token = format!(
        "{SERVICE_TOKEN_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(token_bytes)
    );
    check_token_canonicality(&token, name);
    let bearer = format!("Bearer {token}");
    let mut headers = HeaderMap::new();
    assert_eq!(selected(&headers, name), Err(StatusCode::UNAUTHORIZED));
    headers.insert(header::AUTHORIZATION, bearer.parse().unwrap());
    assert_eq!(selected(&headers, name), Ok(2));
    headers.insert(
        header::AUTHORIZATION,
        format!("bEaReR {token}").parse().unwrap(),
    );
    assert_eq!(selected(&headers, name), Ok(2));
    for malformed in [
        format!("{bearer}="),
        format!("{bearer} "),
        format!("Bearer  {token}"),
    ] {
        headers.insert(header::AUTHORIZATION, malformed.parse().unwrap());
        assert_eq!(selected(&headers, name), Err(StatusCode::UNAUTHORIZED));
    }
    headers.insert(header::AUTHORIZATION, bearer.parse().unwrap());
    headers.append(header::AUTHORIZATION, bearer.parse().unwrap());
    assert_eq!(selected(&headers, name), Err(StatusCode::BAD_REQUEST));
    headers.remove(header::AUTHORIZATION);
    let cookie = format!("{name}=session");
    headers.insert(header::COOKIE, cookie.parse().unwrap());
    assert_eq!(selected(&headers, name), Ok(1));
    headers.insert(header::AUTHORIZATION, bearer.parse().unwrap());
    assert_eq!(selected(&headers, name), Err(StatusCode::BAD_REQUEST));
    headers.remove(header::AUTHORIZATION);
    headers.append(header::COOKIE, cookie.parse().unwrap());
    assert_eq!(selected(&headers, name), Err(StatusCode::BAD_REQUEST));
    headers.insert(
        header::COOKIE,
        format!("{cookie}; {cookie}").parse().unwrap(),
    );
    assert_eq!(selected(&headers, name), Err(StatusCode::BAD_REQUEST));
}

#[cfg(test)]
mod tests {
    #[test]
    fn credential_grammar_examples() {
        for input in [
            b"".as_slice(),
            b"\x01\x00\xff",
            b"\x00\x01\x08Bearer x",
            b"\x00\x00\x02\x80x",
        ] {
            super::check_auth_headers(input);
        }
    }
}
