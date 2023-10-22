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
struct Secret {
    client: SecretPair,
    token: Option<SecretPair>,
}

impl Secret {
    pub fn new<TString>(
        client_key: TString,
        client_secret: TString,
        token_key: Option<TString>,
        token_secret: Option<TString>,
    ) -> Self
    where
        TString: Into<String>,
    {
        Self {
            client: SecretPair {
                key: client_key.into(),
                secret: client_secret.into(),
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
            client: self.client,
            token: Some(SecretPair {
                key: token_key.into(),
                secret: token_secret.into(),
            }),
        }
    }

    pub fn get_client_key(&self) -> String {
        self.client.key.clone()
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
            format!("{}&{}", self.client.secret, token.secret)
        } else {
            format!("{}&", self.client.secret)
        }
    }

    pub fn to_toml<P>(&self, path: P) -> Result<(), SecretError>
    where
        P: AsRef<Path>,
    {
        let s = toml::to_string(self).map_err(|_| {
            SecretError::TOMLError(String::from("Prepare toml information failed."))
        })?;
        fs::write(path, s).map_err(|_| SecretError::IOError(String::from("File write failed.")))?;

        Ok(())
    }

    pub fn from_toml<P>(path: P) -> Result<Self, SecretError>
    where
        P: AsRef<Path>,
    {
        let text = fs::read_to_string(&path)
            .map_err(|_| SecretError::IOError(String::from("File read failed.")))?;
        let s = toml::from_str(&text)
            .map_err(|_| SecretError::TOMLError(String::from("Incompatible key information.")))?;
        Ok(s)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(token) = &self.token {
            write!(
                f,
                "Client Key: {}\nClient Secret: {}\nToken Key: {}\nToken Secret: {}",
                self.client.key, self.client.secret, token.key, token.secret,
            )
        } else {
            write!(
                f,
                "Client Key: {}\nClient Secret: {}",
                self.client.key, self.client.secret,
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
        assert_eq!(res, "Client Key: c1\nClient Secret: c2");
        assert_eq!(secret.get_client_key(), "c1");
        assert_eq!(secret.get_token_key(), None);
        assert_eq!(secret.get_sign_secret(), "c2&");
    }

    #[test]
    fn test_secret_authed() {
        let secret = Secret::new("c1", "c2", None, None).update_token("t1", "t2");
        let res = format!("{}", secret);
        assert_eq!(
            res,
            "Client Key: c1\nClient Secret: c2\nToken Key: t1\nToken Secret: t2"
        );
        assert_eq!(secret.get_token_key(), Some(String::from("t1")));
        assert_eq!(secret.get_sign_secret(), "c2&t2");
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
            "Client Key: c1\nClient Secret: c2\nToken Key: t1\nToken Secret: t2"
        );

        tmp_dir
            .close()
            .map_err(|e| SecretError::IOError(e.to_string()))?;
        Ok(())
    }
}
