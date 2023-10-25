use crate::oauth1::Oauth1;
use crate::secret::{Secret, SecretError};
use reqwest::{self, multipart, Body, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    fmt::{self, Debug},
    path::Path,
};
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};
use url::Position;

const BASE_URL: &str = "https://www.plurk.com";
const REQUEST_TOKEN_URL: &str = "/OAuth/request_token";
const AUTHORIZE_URL: &str = "/OAuth/authorize";
const ACCESS_TOKEN_URL: &str = "/OAuth/access_token";

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

    fn sign(&self, builder: RequestBuilder) -> RequestBuilder {
        let (client, inner) = builder.build_split();
        let request = inner.unwrap();

        let url = &request.url()[..Position::AfterPath];
        let url = url.to_string();
        let method = request.method().to_string();
        let query = if let Some(raw_body) = request.body() {
            if let Some(raw_body) = raw_body.as_bytes() {
                String::from_utf8_lossy(raw_body).to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let oauth = Oauth1::new(self.secret.clone())
            .sign(method, url, query)
            .to_header();

        let builder = RequestBuilder::from_parts(client, request);

        builder.header(reqwest::header::AUTHORIZATION, oauth)
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

    fn parse_oauth_token(raw: String) -> Option<(String, String)> {
        #[derive(Deserialize)]
        struct TmpToken {
            oauth_token: String,
            oauth_token_secret: String,
        }
        match serde_urlencoded::from_str::<TmpToken>(&raw) {
            Ok(token) => Some((token.oauth_token, token.oauth_token_secret)),
            _ => None,
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
