use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process;

use log::{error, info};
use reqwest::{Client, Proxy};
use serde_json;
use toml;
use yaml_rust::{Yaml, YamlLoader};

pub struct Validator {
    client: Client,
}

impl Validator {
    pub fn new(proxy: Option<String>) -> Self {
        let client_builder = Client::builder();
        let client = if let Some(proxy_url) = proxy {
            client_builder
                .proxy(Proxy::all(proxy_url).unwrap())
                .build()
                .unwrap()
        } else {
            client_builder.build().unwrap()
        };
        Validator { client }
    }

    pub async fn validate_proxy(&self, proxy: &str) -> bool {
        let test_url = "https://google.com";
        match self.client.get(test_url).send().await {
            Ok(_) => {
                info!("Proxy is reachable: {}", proxy);
                true
            }
            Err(e) => {
                error!("Failed to reach proxy {}: {}", proxy, e);
                false
            }
        }
    }

    pub async fn validate_target_url(&self, url: &str) -> bool {
        match self.client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Target URL is reachable: {}", url);
                true
            }
            Ok(resp) => {
                error!(
                    "Target URL returned non-success status {}: {}",
                    url,
                    resp.status()
                );
                false
            }
            Err(e) => {
                error!("Failed to reach target URL {}: {}", url, e);
                false
            }
        }
    }

    pub fn validate_config(&self, config_path: Option<&str>) -> bool {
        match config_path {
            Some(path) if Path::new(path).exists() => match fs::read_to_string(path) {
                Ok(contents) => self.check_yaml(&contents, path),
                Err(err) => {
                    error!("Error reading config file {}: {}", path, err);
                    false
                }
            },
            Some(path) => {
                error!("Configuration file does not exist: {}", path);
                false
            }
            None => {
                info!("No configuration file provided; skipping validation.");
                true
            }
        }
    }

    fn check_yaml(&self, contents: &str, path: &str) -> bool {
        match YamlLoader::load_from_str(contents) {
            Ok(docs) => {
                info!(
                    "Checking if YAML configuration file is syntactically correct: {}",
                    path
                );

                let doc = &docs[0];
                if !self.validate_env(doc) {
                    error!("Validation error in 'env' section");
                    return false;
                }

                if !self.validate_jobs(doc) {
                    error!("Validation error in 'jobs' section");
                    return false;
                }

                true
            }
            Err(e) => {
                error!("YAML syntax error in file {}: {}", path, e);
                false
            }
        }
    }

    fn validate_env(&self, doc: &Yaml) -> bool {
        let env = doc["env"]["contexts"].as_vec();
        if env.is_none() || env.unwrap().is_empty() {
            error!("'env.contexts' section is missing or empty");
            return false;
        }

        for context in env.unwrap() {
            if context["urls"]
                .as_vec()
                .map_or(true, |urls| urls.is_empty())
            {
                error!("'urls' section is missing or empty in one of the contexts");
                return false;
            }
        }

        true
    }

    fn validate_jobs(&self, doc: &Yaml) -> bool {
        let jobs = doc["jobs"].as_vec();
        if jobs.is_none() || jobs.unwrap().is_empty() {
            error!("'jobs' section is missing or empty");
            return false;
        }

        for job in jobs.unwrap() {
            if job["type"].as_str().is_none() {
                error!("A job is missing the 'type' field");
                return false;
            }
        }

        true
    }

    fn check_ports_in_use() -> bool {
        let ports = [10923];
        for port in ports.iter() {
            if TcpListener::bind(("127.0.0.1", *port)).is_err() {
                error!(
                    "Port {} is already in use or lacking permission. Exiting...",
                    port
                );
                return true;
            }
        }
        false
    }

    fn validate_toml(&self, contents: &str) -> bool {
        match contents.parse::<toml::Value>() {
            Ok(_) => {
                info!("TOML is syntactically correct");
                true
            }
            Err(e) => {
                error!("TOML syntax error: {}", e);
                false
            }
        }
    }

    fn validate_json(&self, contents: &str) -> bool {
        match serde_json::from_str::<serde_json::Value>(&contents) {
            Ok(_) => {
                info!("JSON is syntactically correct");
                true
            }
            Err(e) => {
                error!("JSON syntax error: {}", e);
                false
            }
        }
    }

    pub async fn run_validations(&self, proxy: &str, url: &str, config: Option<&str>) -> bool {
        if Validator::check_ports_in_use() {
            process::exit(1);
        }

        let mut proxy_valid = true;

        if !proxy.is_empty() {
            proxy_valid = self.validate_proxy(proxy).await;
        }

        let _url_valid = self.validate_target_url(url).await;
        let config_valid = self.validate_config(config);

        let json_contents = fs::read_to_string("src/config/verification_config.json")
            .expect("Failed to read config file");
        let toml_contents = fs::read_to_string("src/config/severity_config.toml")
            .expect("Failed to read config file");

        let valid_json = self.validate_json(&json_contents);
        let valid_toml = self.validate_toml(&toml_contents);

        if !proxy_valid || !config_valid || !valid_json || !valid_toml {
            error!("One or more validations failed. Exiting...");
            process::exit(1);
        }

        true
    }
}
