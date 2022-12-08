use std::path::PathBuf;

use serde::Deserialize;

use crate::{AsResult, Parse};

/// Ssl file format.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SslFileFormat {
    /// rsa
    RSA,
    /// pkcs8
    PKCS8,
}

impl Parse for SslFileFormat {
    fn parse(string: &str) -> AsResult<Self> {
        match string {
            "rsa" => Ok(Self::RSA),
            "pkcs8" => Ok(Self::PKCS8),
            _ => Err(InvalidValue! {
                expected: "\"rsa\" | \"pkcs8\".",
                got: string,
            }),
        }
    }
}

/// TLS (HTTPS) configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[doc(alias = "ssl", alias = "https")]
pub struct Tls {
    /// Tru if accepting TLS connections should be enabled.
    pub enabled: bool,

    /// private key file format
    pub ssl_file_format: SslFileFormat,

    /// Path to certificate `.pem` file.
    pub certificate: PathBuf,

    /// Path to private key `.pem` file.
    pub private_key: PathBuf,
}
