use crate::secret::{Secret, SecretError};
use base64::{engine::general_purpose, Engine};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use reqwest::{self, multipart, Body, RequestBuilder, Response};
use ring::hmac;
use serde::Serialize;
use std::{
    collections::HashMap,
    ffi::OsStr,
    fmt::{self, Debug},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};
use url::Position;

const BASE_URL: &str = "https://www.plurk.com";
const REQUEST_TOKEN_URL: &str = "/OAuth/request_token";
const AUTHORIZE_URL: &str = "/OAuth/authorize";
const ACCESS_TOKEN_URL: &str = "/OAuth/access_token";

type QueryPair = Vec<(String, String)>;

struct Oauth1 {
    inner: QueryPair,
}

impl Oauth1 {
    fn new() -> Self {
        Self {
            inner: vec![
                ("oauth_nonce", Oauth1::gen_nonce(10)),
                ("oauth_timestamp", Oauth1::gen_timestamp()),
                ("oauth_signature_method", "HMAC-SHA1".to_string()),
                ("oauth_version", "1.0".to_string()),
            ]
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        }
    }

    fn gen_timestamp() -> String {
        let start = SystemTime::now();
        start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            .to_string()
    }

    fn gen_nonce(n: usize) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(n)
            .map(char::from)
            .collect()
    }

    fn set_sign(&mut self, sign: impl Into<String>) {
        self.inner
            .push((String::from("oauth_signature"), sign.into()));
    }

    fn to_header(&self) -> String {
        let mut oauth_header = self
            .inner
            .iter()
            .filter(|x| x.0.starts_with("oauth_"))
            .map(|x| format!(" {}=\"{}\",", x.0, x.1))
            .collect::<String>();
        oauth_header.pop();
        format!("OAuth{oauth_header}")
    }

    fn extend(&mut self, items: QueryPair) {
        self.inner.extend(items)
    }

    fn sort(&mut self) {
        self.inner.sort_by(|a, b| a.0.cmp(&b.0));
    }

    fn get_inner(&self) -> QueryPair {
        self.inner.clone()
    }
}

impl Default for Oauth1 {
    fn default() -> Self {
        Self::new()
    }
}

fn hmac_sha1_sign(sign_url: String, sign_key: String) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, sign_key.as_bytes());
    let h = hmac::sign(&key, sign_url.as_bytes());
    let sign = general_purpose::STANDARD.encode(&h);
    url_escape::encode_www_form_urlencoded(&sign).to_string()
}

#[derive(Debug)]
pub enum PlurkError {
    ReqwestError(reqwest::Error),
    APICallError(String),
    AuthError(String),
    SecretError(SecretError),
}

impl fmt::Display for PlurkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ReqwestError(e) => write!(f, "reqwest error: {}", e),
            Self::APICallError(e) => write!(f, "API Request Error: {}", e),
            Self::AuthError(e) => write!(f, "Authorization Error: {}", e),
            Self::SecretError(e) => write!(f, "Secret Error: {}", e),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Plurk {
    secret: Secret,
}

impl Plurk {
    pub fn new<TString>(
        consumer_key: TString,
        consumer_secret: TString,
        token_key: Option<TString>,
        token_secret: Option<TString>,
    ) -> Self
    where
        TString: Into<String>,
    {
        Self {
            secret: Secret::new(consumer_key, consumer_secret, token_key, token_secret),
        }
    }

    pub fn is_auth(&self) -> bool {
        self.secret.get_token_key().is_some()
    }

    fn update_token<S: Into<String>>(&mut self, token_key: S, token_secret: S) {
        self.secret.update_token_mut(token_key, token_secret);
    }

    fn prep_cmd(api: impl Into<String>) -> String {
        format!("{}{}", BASE_URL, api.into())
    }

    fn to_oauth(&self) -> QueryPair {
        let mut key_query = Vec::new();

        if !self.secret.get_consumer_key().is_empty() {
            key_query.push((
                String::from("oauth_consumer_key"),
                self.secret.get_consumer_key(),
            ));
        }
        if let Some(token_key) = self.secret.get_token_key() {
            key_query.push((String::from("oauth_token"), token_key));
        }

        key_query
    }

    fn sign(&self, builder: RequestBuilder) -> RequestBuilder {
        // 1. Get Request
        let (client, inner) = builder.build_split();
        let mut request = inner.unwrap();

        // 2. Get Query
        let url = request.url().clone();
        let method = request.method().to_string();

        // 3. Mix to oauth pool, sort by first alphabet
        let mut auth = Oauth1::new();
        let keys = self.to_oauth();
        auth.extend(keys);

        if let Some(raw_body) = request.body() {
            let raw_body = raw_body.as_bytes().unwrap();
            let body = String::from_utf8_lossy(raw_body).to_string();
            let query = Plurk::parse_query(body);
            auth.extend(query.clone());

            let mut query = query;

            query.retain(|x| !x.0.starts_with("oauth_"));

            if let Ok(body) = serde_urlencoded::to_string(query) {
                *request.body_mut() = Some(body.into());
            }
        }

        auth.sort();

        // 4. Get sign url
        let raw_base_url = &url[..Position::AfterPath];
        let base_url = url_escape::encode_www_form_urlencoded(raw_base_url);

        let raw_query_part = if let Ok(body) = serde_urlencoded::to_string(auth.get_inner()) {
            body
        } else {
            String::new()
        };
        let query_part = url_escape::encode_www_form_urlencoded(&raw_query_part);
        let sign_url = format!("{}&{}&{}", method, base_url, query_part);

        // 5. Get sign key
        let sign_key = self.secret.get_sign_secret();

        // 6. Cal signature
        let sign = hmac_sha1_sign(sign_url, sign_key);

        // 7. Write to oauth
        auth.set_sign(sign);
        let header = auth.to_header();

        let builder = RequestBuilder::from_parts(client, request);

        builder.header(reqwest::header::AUTHORIZATION, header)
    }

    async fn file_to_multipart<TPath>(file: (String, TPath)) -> Result<multipart::Form, PlurkError>
    where
        TPath: AsRef<Path> + std::convert::AsRef<OsStr>,
    {
        let file_obj = File::open(&file.1)
            .await
            .map_err(|e| PlurkError::APICallError(e.to_string()))?;
        let file_name = Path::new(&file.1)
            .file_name()
            .ok_or(PlurkError::APICallError(String::from(
                "Cannot get file name.",
            )))?;

        // Just convert type, ignore result
        let file_name = file_name.to_os_string().into_string().unwrap();

        let stream = FramedRead::new(file_obj, BytesCodec::new());
        let file_body = Body::wrap_stream(stream);

        let prep_file = multipart::Part::stream(file_body)
            .file_name(file_name)
            .mime_str("multipart/form-data")
            .map_err(|e| PlurkError::APICallError(e.to_string()))?;

        Ok(multipart::Form::new().part(file.0, prep_file))
    }

    pub async fn request<TQuery, TString, TPath>(
        &self,
        api: TString,
        query: Option<TQuery>,
        file: Option<(String, TPath)>,
    ) -> Result<Response, PlurkError>
    where
        TQuery: Serialize,
        TString: Into<String>,
        TPath: AsRef<Path> + AsRef<OsStr>,
    {
        // Accept order file > query
        let query = if file.is_some() { None } else { query };

        let request = reqwest::Client::new().post(Plurk::prep_cmd(api));

        // Add query
        let request = if let Some(q) = query {
            request.form(&q)
        } else {
            request
        };

        // Add multipart for image
        let request = if let Some(f) = file {
            let form = Plurk::file_to_multipart(f).await?;

            request.multipart(form)
        } else {
            request
        };

        // Sign oauth1
        let request = self.sign(request);

        request
            .send()
            .await
            .map_err(|e| PlurkError::ReqwestError(e))
    }

    pub fn get_auth_url(&self) -> Result<String, PlurkError> {
        if let Some(token_key) = self.secret.get_token_key() {
            Ok(format!(
                "{}?oauth_token={}",
                Plurk::prep_cmd(AUTHORIZE_URL),
                token_key
            ))
        } else {
            Err(PlurkError::AuthError(
                "Missing requested token key".to_string(),
            ))
        }
    }

    fn parse_query(raw: String) -> QueryPair {
        querystring::querify(&raw)
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    fn parse_oauth_token(raw: String) -> Option<(String, String)> {
        let qs = querystring::querify(&raw);
        let hashed_qs: HashMap<String, String> = qs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        if let (Some(key), Some(secret)) = (
            hashed_qs.get("oauth_token"),
            hashed_qs.get("oauth_token_secret"),
        ) {
            Some((key.to_string(), secret.to_string()))
        } else {
            None
        }
    }

    pub async fn request_auth(&mut self) -> Result<(), PlurkError> {
        let resp = self
            .request(
                REQUEST_TOKEN_URL,
                Some([("oauth_callback", "oob")]),
                None::<(String, String)>,
            )
            .await?
            .text()
            .await
            .map_err(|e| PlurkError::ReqwestError(e))?;

        if let Some((key, secret)) = Plurk::parse_oauth_token(resp) {
            self.update_token(key, secret);
        }

        Ok(())
    }

    pub async fn verify_auth<T>(&mut self, pin: T) -> Result<(), PlurkError>
    where
        T: AsRef<str> + Debug + Serialize,
    {
        let resp = self
            .request(
                ACCESS_TOKEN_URL,
                Some([("oauth_verifier", &pin)]),
                None::<(String, String)>,
            )
            .await?
            .text()
            .await
            .map_err(|e| PlurkError::ReqwestError(e))?;

        if let Some((key, secret)) = Plurk::parse_oauth_token(resp) {
            self.update_token(key, secret);
        }
        Ok(())
    }

    pub fn to_toml<P>(&self, path: P) -> Result<(), PlurkError>
    where
        P: AsRef<Path>,
    {
        self.secret
            .to_toml(path)
            .map_err(|e| PlurkError::SecretError(e))
    }

    pub fn from_toml<P>(path: P) -> Result<Self, PlurkError>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            secret: Secret::from_toml(path).map_err(|e| PlurkError::SecretError(e))?,
        })
    }
}

impl fmt::Display for Plurk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Plurk API {} ({})", self.secret.get_consumer_key(), {
            if self.is_auth() {
                "Authorized"
            } else {
                "Unauthorized"
            }
        })
    }
}
