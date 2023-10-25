use crate::secret::Secret;
use base64::{engine::general_purpose, Engine};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use ring::hmac;
use std::time::{SystemTime, UNIX_EPOCH};

type QueryPair = Vec<(String, String)>;

pub struct Oauth1 {
    oauth_consumer_key: String,
    oauth_token: Option<String>,
    oauth_signature_method: String,
    oauth_signature: String,
    oauth_timestamp: String,
    oauth_nonce: String,
    oauth_version: String,
    oauth_callback: Option<String>,
    oauth_verifier: Option<String>,
    realm: Option<String>,
    sign_key: String,
}

impl Oauth1 {
    pub fn new(secret: Secret) -> Self {
        Self {
            oauth_consumer_key: secret.get_consumer_key(),
            oauth_token: secret.get_token_key(),
            oauth_signature_method: String::from("HMAC-SHA1"),
            oauth_signature: String::new(),
            oauth_timestamp: Oauth1::gen_timestamp(),
            oauth_nonce: Oauth1::gen_nonce(10),
            oauth_version: String::from("1.0"),
            oauth_callback: None,
            oauth_verifier: None,
            realm: None,
            sign_key: secret.get_sign_secret(),
        }
    }

    fn to_query_pair(&self) -> QueryPair {
        let mut res: QueryPair = Vec::new();

        if let Some(call_back) = &self.oauth_callback {
            res.push(("oauth_callback".into(), call_back.into()));
        }
        res.push(("oauth_consumer_key".into(), self.oauth_consumer_key.clone()));
        res.push(("oauth_nonce".into(), self.oauth_nonce.clone()));
        res.push((
            "oauth_signature_method".into(),
            self.oauth_signature_method.clone(),
        ));
        res.push(("oauth_timestamp".into(), self.oauth_timestamp.clone()));
        if let Some(token) = &self.oauth_token {
            res.push(("oauth_token".into(), token.into()));
        }
        if let Some(verifier) = &self.oauth_verifier {
            res.push(("oauth_verifier".into(), verifier.into()));
        }
        res.push(("oauth_version".into(), self.oauth_version.clone()));
        res
    }

    pub fn to_header(&self) -> String {
        let mut res = format!("OAuth ");

        if let Some(realm) = &self.realm {
            res.push_str(&format!("realm=\"{}\", ", realm));
        }

        // Sort by properity name
        if let Some(call_back) = &self.oauth_callback {
            res.push_str(&format!("oauth_callback=\"{}\", ", call_back));
        }
        res.push_str(&format!(
            "oauth_consumer_key=\"{}\", ",
            self.oauth_consumer_key
        ));
        res.push_str(&format!("oauth_nonce=\"{}\", ", self.oauth_nonce));
        res.push_str(&format!("oauth_signature=\"{}\", ", self.oauth_signature));
        res.push_str(&format!(
            "oauth_signature_method=\"{}\", ",
            self.oauth_signature_method
        ));
        res.push_str(&format!("oauth_timestamp=\"{}\", ", self.oauth_timestamp));
        if let Some(token) = &self.oauth_token {
            res.push_str(&format!("oauth_token=\"{}\", ", token));
        }
        if let Some(verifier) = &self.oauth_verifier {
            res.push_str(&format!("oauth_verifier=\"{}\", ", verifier));
        }
        res.push_str(&format!("oauth_version=\"{}\", ", self.oauth_version));

        // Remove last ", "
        res.pop();
        res.pop();
        res
    }

    fn get_value_by_key<'a>(key: &str, data: &'a QueryPair) -> Option<String> {
        data.iter()
            .find_map(|(k, v)| if k == key { Some(v.clone()) } else { None })
    }

    pub fn sign<T>(mut self, method: T, uri: T, query: T) -> Self
    where
        T: Into<String>,
    {
        let mut query_poll: QueryPair =
            serde_urlencoded::from_str(&query.into()).unwrap_or(Vec::new());

        query_poll.extend(self.to_query_pair());
        query_poll.sort_by(|a, b| a.0.cmp(&b.0));

        let uri = uri.into();
        let encoded_uri = url_escape::encode_www_form_urlencoded(&uri);

        let raw_query_part = serde_urlencoded::to_string(&query_poll).unwrap_or(String::new());
        let encoded_query = url_escape::encode_www_form_urlencoded(&raw_query_part);

        let sign_base = format!("{}&{}&{}", method.into(), encoded_uri, encoded_query);
        let sign = Self::hmac_sha1_sign(sign_base, self.sign_key.clone());

        self.oauth_signature = sign;
        self.oauth_callback = Self::get_value_by_key("oauth_callback", &query_poll);
        self.oauth_verifier = Self::get_value_by_key("oauth_verifier", &query_poll);
        self.realm = Some(uri.into());

        self
    }

    fn hmac_sha1_sign(sign_url: String, sign_key: String) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, sign_key.as_bytes());
        let h = hmac::sign(&key, sign_url.as_bytes());
        let sign = general_purpose::STANDARD.encode(&h);
        url_escape::encode_www_form_urlencoded(&sign).to_string()
    }

    #[cfg(test)]
    fn test_set_callback<T>(mut self, s: T) -> Self
    where
        T: Into<String>,
    {
        self.oauth_callback = Some(s.into());
        self
    }

    #[cfg(test)]
    fn test_set_verifier<T>(mut self, s: T) -> Self
    where
        T: Into<String>,
    {
        self.oauth_verifier = Some(s.into());
        self
    }

    #[cfg(test)]
    fn test_set_nonce<T>(mut self, s: T) -> Self
    where
        T: Into<String>,
    {
        self.oauth_nonce = s.into();
        self
    }

    #[cfg(test)]
    fn test_set_timestamp<T>(mut self, s: T) -> Self
    where
        T: Into<String>,
    {
        self.oauth_timestamp = s.into();
        self
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request() {
        let secret = Secret::new("c1", "c2", None, None);
        let oauth = Oauth1::new(secret)
            .test_set_nonce("aabbcc123")
            .test_set_timestamp("1191242096")
            .test_set_callback("oob")
            .sign("POST", "https://www.example.com/API/foo", "a=1&b=2&ooo=345")
            .to_header();
        assert_eq!(
            oauth,
            "OAuth realm=\"https://www.example.com/API/foo\", \
            oauth_callback=\"oob\", \
            oauth_consumer_key=\"c1\", \
            oauth_nonce=\"aabbcc123\", \
            oauth_signature=\"qam71izC3bro%2FDWpwJq9PYwgZu4%3D\", \
            oauth_signature_method=\"HMAC-SHA1\", \
            oauth_timestamp=\"1191242096\", \
            oauth_version=\"1.0\""
        );
    }

    #[test]
    fn test_verify() {
        let secret = Secret::new("c1", "c2", None, None).update_token("t1", "t2");
        let oauth = Oauth1::new(secret)
            .test_set_nonce("aabbcc123")
            .test_set_timestamp("1191242096")
            .test_set_verifier("5566")
            .sign("POST", "https://www.example.com/API/foo", "a=1&b=2&ooo=345")
            .to_header();
        assert_eq!(
            oauth,
            "OAuth realm=\"https://www.example.com/API/foo\", \
            oauth_consumer_key=\"c1\", \
            oauth_nonce=\"aabbcc123\", \
            oauth_signature=\"KRfqrNw25YTQUi9SvV6%2Fguq9YUQ%3D\", \
            oauth_signature_method=\"HMAC-SHA1\", \
            oauth_timestamp=\"1191242096\", \
            oauth_token=\"t1\", \
            oauth_verifier=\"5566\", \
            oauth_version=\"1.0\""
        );
    }

    #[test]
    fn test_auto_parse_oauth_param() {
        let secret = Secret::new("c1", "c2", None, None).update_token("t1", "t2");
        let oauth = Oauth1::new(secret)
            .test_set_nonce("aabbcc123")
            .test_set_timestamp("1191242096")
            .sign(
                "POST",
                "https://www.example.com/API/foo",
                "a=1&b=2&ooo=345&oauth_verifier=5566",
            )
            .to_header();
        assert_eq!(
            oauth,
            "OAuth realm=\"https://www.example.com/API/foo\", \
            oauth_consumer_key=\"c1\", \
            oauth_nonce=\"aabbcc123\", \
            oauth_signature=\"KRfqrNw25YTQUi9SvV6%2Fguq9YUQ%3D\", \
            oauth_signature_method=\"HMAC-SHA1\", \
            oauth_timestamp=\"1191242096\", \
            oauth_token=\"t1\", \
            oauth_verifier=\"5566\", \
            oauth_version=\"1.0\""
        );
    }

    #[test]
    fn test_access() {
        let secret = Secret::new("c1", "c2", None, None).update_token("t3", "t4");
        let oauth = Oauth1::new(secret)
            .test_set_nonce("aabbcc123")
            .test_set_timestamp("1191242096")
            .sign("POST", "https://www.example.com/API/foo", "a=1&b=2&ooo=345")
            .to_header();
        assert_eq!(
            oauth,
            "OAuth realm=\"https://www.example.com/API/foo\", \
                   oauth_consumer_key=\"c1\", \
                   oauth_nonce=\"aabbcc123\", \
                   oauth_signature=\"Q4dy5DkLybAOoGz0qcqW58mTUPc%3D\", \
                   oauth_signature_method=\"HMAC-SHA1\", \
                   oauth_timestamp=\"1191242096\", \
                   oauth_token=\"t3\", \
                   oauth_version=\"1.0\""
        );
    }

    #[test]
    fn test_query() {
        let secret = Secret::new("c1", "c2", None, None).update_token("t3", "t4");
        let oauth = Oauth1::new(secret)
            .test_set_nonce("aabbcc123")
            .test_set_timestamp("1191242096")
            .sign(
                "POST",
                "https://www.example.com/API/foo",
                "a=1&b=2&ooo=345+",
            )
            .to_header();
        assert_eq!(
            oauth,
            "OAuth realm=\"https://www.example.com/API/foo\", \
                   oauth_consumer_key=\"c1\", \
                   oauth_nonce=\"aabbcc123\", \
                   oauth_signature=\"DGrj27ipWXGB5Qv0aQ0hJenC6%2B4%3D\", \
                   oauth_signature_method=\"HMAC-SHA1\", \
                   oauth_timestamp=\"1191242096\", \
                   oauth_token=\"t3\", \
                   oauth_version=\"1.0\""
        );
    }

    #[test]
    fn test_extra_oauth_param() {
        let secret = Secret::new("c1", "c2", None, None).update_token("t3", "t4");
        let oauth = Oauth1::new(secret)
            .test_set_nonce("aabbcc123")
            .test_set_timestamp("1191242096")
            .sign(
                "POST",
                "https://www.example.com/API/foo",
                "a=1&b=2&ooo=345+&oauth_unknown=112",
            )
            .to_header();
        assert_eq!(
            oauth,
            "OAuth realm=\"https://www.example.com/API/foo\", \
                   oauth_consumer_key=\"c1\", \
                   oauth_nonce=\"aabbcc123\", \
                   oauth_signature=\"odO8x3BWLT9SdokzdGG99%2BOZb84%3D\", \
                   oauth_signature_method=\"HMAC-SHA1\", \
                   oauth_timestamp=\"1191242096\", \
                   oauth_token=\"t3\", \
                   oauth_version=\"1.0\""
        );
    }

    #[test]
    fn test_clean() {
        let secret = Secret::new("c1", "c2", None, None).update_token("t3", "t4");
        let oauth = Oauth1::new(secret)
            .test_set_nonce("aabbcc123")
            .test_set_timestamp("1191242096")
            .sign("POST", "https://www.example.com/API/foo", "")
            .to_header();
        assert_eq!(
            oauth,
            "OAuth realm=\"https://www.example.com/API/foo\", \
                   oauth_consumer_key=\"c1\", \
                   oauth_nonce=\"aabbcc123\", \
                   oauth_signature=\"wStrZYCwsImMLtk4CwB3whzGoOA%3D\", \
                   oauth_signature_method=\"HMAC-SHA1\", \
                   oauth_timestamp=\"1191242096\", \
                   oauth_token=\"t3\", \
                   oauth_version=\"1.0\""
        );
    }
}
