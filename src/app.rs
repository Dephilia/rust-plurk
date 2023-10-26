use clap::Parser;
use reqwest::StatusCode;
use rust_plurk::plurk::{Plurk, PlurkError};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

/// Plurk API test tool
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Oauth KEY
    #[arg(short = 'k', long)]
    consumer_key: Option<String>,

    /// Oauth SECRET
    #[arg(short = 's', long)]
    consumer_secret: Option<String>,

    /// Oauth token KEY
    #[arg(short = 'K', long)]
    token_key: Option<String>,

    /// Oauth token SECRET
    #[arg(short = 'S', long)]
    token_secret: Option<String>,

    /// Oauth toml file
    #[arg(short = 't', long)]
    key_file: Option<String>,

    /// API Path
    #[arg(short = 'i', long)]
    api: String,

    /// Optional argument with file path. Format: -f "key,path"
    #[arg(short = 'f', long)]
    file: Option<String>,

    /// Optional parameters. Format: -q "key1,value1" -q "key2,value2"
    #[arg(short = 'q', long)]
    query: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OauthToml {
    consumer: OauthKeys,
    oauth_token: Option<OauthKeys>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OauthKeys {
    key: String,
    secret: String,
}

#[tokio::main]
async fn main() -> Result<(), PlurkError> {
    let cli = Cli::parse();

    let plurk = match (cli.consumer_key, cli.consumer_secret, cli.key_file.clone()) {
        (Some(consumer_key), Some(consumer_secret), None) => Plurk::new(
            consumer_key,
            consumer_secret,
            cli.token_key,
            cli.token_secret,
        ),
        (_, _, Some(key_file)) => Plurk::from_toml(key_file)?,
        _ => {
            println!("Invalid consumer key/secret or key_file.");
            return Ok(());
        }
    };

    let plurk = if !plurk.is_auth() {
        let mut plurk = plurk;
        plurk.request_auth().await?;
        let url = plurk.get_auth_url()?;
        println!("Please access to: {}", url);
        print!("Input pin:");
        io::stdout().flush().expect("Flush failed");

        let mut user_input = String::new();
        io::stdin()
            .read_line(&mut user_input)
            .expect("Failed to read the user input");
        let pin = user_input.trim();
        plurk.verify_auth(pin).await?;
        plurk
    } else {
        plurk
    };

    if let Some(key_file) = cli.key_file {
        plurk.to_toml(key_file)?;
    }

    let parameters: Option<Vec<(String, String)>> = cli.query.map(|query| {
        query
            .iter()
            .map(|pair_raw| {
                let mut iter = pair_raw.splitn(2, ',').map(|s| s.trim().to_string());
                (
                    iter.next().unwrap_or_default(),
                    iter.next().unwrap_or_default(),
                )
            })
            .collect()
    });

    let file_parameters: Option<(String, String)> = cli.file.map(|pair_raw| {
        let mut iter = pair_raw.splitn(2, ',').map(|s| s.trim().to_string());
        (
            iter.next().unwrap_or_default(),
            iter.next().unwrap_or_default(),
        )
    });

    let res = plurk.request(cli.api, parameters, file_parameters).await?;

    match res.status() {
        StatusCode::OK => (),
        StatusCode::BAD_REQUEST => {
            println!("Error: {}", &res.status());
        }
        _ => {
            println!("Error: {}", &res.status());
            return Ok(());
        }
    }

    if res.headers()["content-type"] != "application/json" {
        println!("Response is not json type. Maybe call the wrong API or Oauth error.");
        return Ok(());
    }

    let parsed_res: serde_json::Value = res.json().await.expect("To json failed.");

    let pretty = serde_json::to_string_pretty(&parsed_res).expect("Format json failed.");
    println!("{}", pretty);

    Ok(())
}
