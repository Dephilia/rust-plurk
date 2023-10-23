use serde::{Deserialize, Serialize};
use std::{fmt, fs, path::Path};

#[derive(Debug)]
pub enum SecretError {
    IOError(String),
    TOMLError(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::IOError(e) => write!(f, "IO Error: {}", e),
            Self::TOMLError(e) => write!(f, "TOML Error: {}", e),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SecretPair {
    key: String,
    secret: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Secret {
    consumer: SecretPair,
    token: Option<SecretPair>,
}

impl Secret {
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
            consumer: SecretPair {
                key: consumer_key.into(),
                secret: consumer_secret.into(),
            },
            token: if let (Some(key), Some(secret)) = (token_key, token_secret) {
                Some(SecretPair {
                    key: key.into(),
                    secret: secret.into(),
                })
            } else {
                None
            },
        }
    }

    pub fn update_token<TString>(self, token_key: TString, token_secret: TString) -> Self
    where
        TString: Into<String>,
    {
        Self {
            consumer: self.consumer,
            token: Some(SecretPair {
                key: token_key.into(),
                secret: token_secret.into(),
            }),
        }
    }

    pub fn update_token_mut<TString>(&mut self, token_key: TString, token_secret: TString)
    where
        TString: Into<String>,
    {
        self.token = Some(SecretPair {
            key: token_key.into(),
            secret: token_secret.into(),
        });
    }

    pub fn get_consumer_key(&self) -> String {
        self.consumer.key.clone()
    }

    pub fn get_token_key(&self) -> Option<String> {
        if let Some(token) = &self.token {
            Some(token.key.clone())
        } else {
            None
        }
    }

    pub fn get_sign_secret(&self) -> String {
        if let Some(token) = &self.token {
            format!("{}&{}", self.consumer.secret, token.secret)
        } else {
            format!("{}&", self.consumer.secret)
        }
    }

    pub fn to_toml<P>(&self, path: P) -> Result<(), SecretError>
    where
        P: AsRef<Path>,
    {
        let s = toml::to_string(self).map_err(|e| SecretError::TOMLError(e.to_string()))?;
        fs::write(path, s).map_err(|e| SecretError::IOError(e.to_string()))?;
        Ok(())
    }

    pub fn from_toml<P>(path: P) -> Result<Self, SecretError>
    where
        P: AsRef<Path>,
    {
        let text = fs::read_to_string(&path).map_err(|e| SecretError::IOError(e.to_string()))?;
        let s = toml::from_str(&text).map_err(|e| SecretError::TOMLError(e.to_string()))?;
        Ok(s)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(token) = &self.token {
            write!(
                f,
                "Consumer Key: {}\nConsumer Secret: {}\nToken Key: {}\nToken Secret: {}",
                self.consumer.key, self.consumer.secret, token.key, token.secret,
            )
        } else {
            write!(
                f,
                "Consumer Key: {}\nConsumer Secret: {}",
                self.consumer.key, self.consumer.secret,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_secret_unauthed() {
        let secret = Secret::new("c1", "c2", None, None);
        let res = format!("{}", secret);
        assert_eq!(res, "Consumer Key: c1\nConsumer Secret: c2");
        assert_eq!(secret.get_consumer_key(), "c1");
        assert_eq!(secret.get_token_key(), None);
        assert_eq!(secret.get_sign_secret(), "c2&");
    }

    #[test]
    fn test_secret_authed() {
        let secret = Secret::new("c1", "c2", None, None).update_token("t1", "t2");
        let res = format!("{}", secret);
        assert_eq!(
            res,
            "Consumer Key: c1\nConsumer Secret: c2\nToken Key: t1\nToken Secret: t2"
        );
        assert_eq!(secret.get_token_key(), Some(String::from("t1")));
        assert_eq!(secret.get_sign_secret(), "c2&t2");
        let mut secret = secret;
        secret.update_token_mut("t3", "t4");
        let res = format!("{}", secret);
        assert_eq!(
            res,
            "Consumer Key: c1\nConsumer Secret: c2\nToken Key: t3\nToken Secret: t4"
        );
    }

    #[test]
    fn test_toml() -> Result<(), SecretError> {
        let secret = Secret::new("c1", "c2", None, None).update_token("t1", "t2");

        let tmp_dir = TempDir::new("test_toml").map_err(|e| SecretError::IOError(e.to_string()))?;
        let file_path = tmp_dir.path().join("key.toml");

        secret.to_toml(&file_path)?;

        let secret = Secret::from_toml(&file_path)?;

        let res = format!("{}", secret);
        assert_eq!(
            res,
            "Consumer Key: c1\nConsumer Secret: c2\nToken Key: t1\nToken Secret: t2"
        );

        tmp_dir
            .close()
            .map_err(|e| SecretError::IOError(e.to_string()))?;
        Ok(())
    }

    #[test]
    fn test_error() {
        let res = format!("{}", SecretError::IOError(String::from("abc")));
        assert_eq!(res, "IO Error: abc");

        let res = format!("{}", SecretError::TOMLError(String::from("abc")));
        assert_eq!(res, "TOML Error: abc");
    }
}
