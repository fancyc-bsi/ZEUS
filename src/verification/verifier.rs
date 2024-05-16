use std::{error::Error, path::Path};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use colored::*;
use log::{info, warn};
use md5::{Digest, Md5};
use regex::Regex;
use reqwest::{Client, Proxy};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use thirtyfour::FirefoxCapabilities;
use thirtyfour::WebDriver;

// verifier.rs
use crate::results_parser::parser::Finding;
use crate::utils::setup_warp::add_html_content;
use crate::zap_integration::zap_client::ZapError;

// use crate::translator::generate_curl_command;

#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationConfig {
    pub findings: Vec<FindingConfig>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FindingConfig {
    pub name: String,
    pub wstg_category: Option<String>,
    matcher: Matcher,
    pub screenshot_required: bool,
    pub screenshot_type: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Matcher {
    Status {
        status_code: u16,
    },
    Regex {
        scope: MatchScope,
        pattern: String,
    },
    Word {
        scope: MatchScope,
        word: String,
    },
    Reverse {
        headers: Vec<String>,
    },
    Compound {
        logic: String,
        conditions: Vec<Matcher>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum MatchScope {
    Body,
    Header,
}

impl VerificationConfig {
    fn load() -> Self {
        let path = Path::new("src/config/verification_config.json");

        let mut file = File::open(path).expect("Failed to open config file");

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read config file");

        serde_json::from_str(&contents).expect("Error parsing config JSON")
    }
}

#[derive(Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub request: Option<String>,
    pub response: Option<String>,
    pub match_note: Option<String>,
}

pub struct Verifier {
    pub config: VerificationConfig,
    pub client: Client,
    pub proxy_option: Option<String>,
    pub driver: Option<WebDriver>,
}

impl Verifier {
    pub fn new(proxy: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let config = VerificationConfig::load();

        let client_builder = Client::builder();
        let client = if let Some(proxy_url) = proxy {
            let formatted_proxy_url =
                if proxy_url.starts_with("http://") || proxy_url.starts_with("https://") {
                    String::from(proxy_url)
                } else {
                    format!("http://{}", proxy_url)
                };
            client_builder
                .proxy(Proxy::all(&formatted_proxy_url)?)
                .build()?
        } else {
            client_builder.build()?
        };

        let proxy_option = proxy.map(String::from);

        Ok(Verifier {
            config,
            client,
            proxy_option,
            driver: None,
        })
    }

    pub async fn verify(
        &mut self,
        finding: &Finding,
        project_folder: &PathBuf,
    ) -> Result<VerificationResult, ZapError> {
        let mut result = VerificationResult {
            verified: false,
            request: None,
            response: None,
            match_note: None,
        };
        if let Some(finding_config) = self.config.findings.iter().find(|f| f.name == finding.name) {
            for uri in &finding.uris {
                let response = self
                    .client
                    .get(uri)
                    .send()
                    .await
                    .map_err(ZapError::Reqwest)?;

                let headers_for_screenshot = response.headers().clone();
                let headers_for_report = response.headers().clone();

                let status_code = response.status().as_u16();
                let body_text = response.text().await.map_err(ZapError::Reqwest)?;

                let (match_result, note) = self
                    .match_response(
                        status_code,
                        &headers_for_report,
                        &body_text,
                        &finding_config.matcher,
                    )
                    .await?;
                result.verified = match_result;

                if result.verified {
                    result.request = Some(format!("GET {}", uri));

                    let formatted_headers_for_screenshot = self.format_headers_for_screenshot(
                        &finding.name,
                        &headers_for_screenshot,
                        uri,
                        &note,
                    );
                    let formatted_headers_for_report =
                        self.format_headers_for_report(&headers_for_report);
                    result.response = Some(format!(
                        "headers: {{{}}}\n\n{}",
                        formatted_headers_for_report, body_text
                    ));
                    result.match_note = Some(note);

                    if finding_config.screenshot_required {
                        let screenshot_type =
                            finding_config.screenshot_type.as_deref().unwrap_or("web");

                        let mut hasher = Md5::new();
                        hasher.update(finding.name.to_lowercase().as_bytes());
                        let hash_result = hasher.finalize();
                        let screenshot_filename = format!("{:x}.png", hash_result);
                        let screenshot_path = project_folder.join(screenshot_filename);

                        match screenshot_type {
                            "web" => {
                                self.take_web_screenshot(&finding.name, uri, &screenshot_path)
                                    .await
                                    .expect("Failed to take page screenshot");
                            }
                            "file" => {
                                let html_content_for_screenshot = format!(
                                    "<html><body>{}</body></html>",
                                    formatted_headers_for_screenshot
                                );
                                self.render_html_screenshot(
                                    &finding.name,
                                    &html_content_for_screenshot,
                                    &screenshot_path,
                                )
                                .await
                                .expect("Failed to take HTML content screenshot");
                            }
                            _ => eprintln!("Unsupported screenshot type: {}", screenshot_type),
                        }
                    }
                    return Ok(result);
                }
            }
        }
        warn!("No match found or verified for finding: {}", finding.name);
        Ok(result)
    }

    async fn match_response(
        &self,
        status_code: u16,
        response_headers: &HeaderMap,
        body_text: &str,
        matcher: &Matcher,
    ) -> Result<(bool, String), ZapError> {
        match matcher {
            Matcher::Status {
                status_code: expected_status,
            } => self
                .match_status(status_code, *expected_status)
                .map(|res| {
                    (
                        res,
                        format!("Status match: {} == {}", status_code, expected_status),
                    )
                })
                .map_err(ZapError::from),
            Matcher::Regex { scope, pattern } => self
                .match_regex(scope, pattern, response_headers, body_text)
                .await
                .map(|res| (res, format!("Regex match on {:?}: {}", scope, pattern)))
                .map_err(ZapError::from),
            Matcher::Word { scope, word } => self
                .match_word(scope, word, response_headers, body_text)
                .await
                .map(|res| (res, format!("Word match on {:?}: {}", scope, word)))
                .map_err(ZapError::from),
            Matcher::Reverse { headers } => self
                .match_reverse(headers, response_headers)
                .await
                .map(|res| {
                    (
                        res,
                        format!(
                            "Reverse match - target header not found in response: {:?}",
                            headers
                        ),
                    )
                })
                .map_err(ZapError::from),
            Matcher::Compound { logic, conditions } => {
                let results = futures::future::join_all(conditions.iter().map(|condition| {
                    self.match_response(status_code, response_headers, body_text, condition)
                }))
                .await;

                let all_results = results.into_iter().collect::<Result<Vec<_>, _>>()?;
                let all_notes = all_results
                    .iter()
                    .map(|(_, note)| note.clone())
                    .collect::<Vec<_>>()
                    .join(", ");

                match logic.as_str() {
                    "and" => Ok((
                        all_results.iter().all(|(r, _)| *r),
                        format!("Compound AND match: [{}]", all_notes),
                    )),
                    "or" => Ok((
                        all_results.iter().any(|(r, _)| *r),
                        format!("Compound OR match: [{}]", all_notes),
                    )),
                    _ => Err(ZapError::Other("Invalid logic operator".into())),
                }
            }
        }
    }

    fn match_status(&self, status_code: u16, expected_status: u16) -> Result<bool, ZapError> {
        Ok(status_code == expected_status)
    }

    async fn match_regex(
        &self,
        scope: &MatchScope,
        pattern: &str,
        response_headers: &HeaderMap,
        body_text: &str,
    ) -> Result<bool, ZapError> {
        let regex = Regex::new(pattern)
            .map_err(|e| ZapError::Other(format!("Invalid regex pattern: {}", e)))?;

        match scope {
            MatchScope::Body => Ok(regex.is_match(body_text)),
            MatchScope::Header => {
                let all_headers_value = response_headers
                    .iter()
                    .map(|(key, value)| format!("{}: {}", key, value.to_str().unwrap_or("")))
                    .collect::<Vec<String>>()
                    .join("\n");

                Ok(regex.is_match(&all_headers_value))
            }
        }
    }

    async fn match_word(
        &self,
        scope: &MatchScope,
        word: &String,
        response_headers: &HeaderMap,
        body_text: &str,
    ) -> Result<bool, ZapError> {
        Ok(match scope {
            MatchScope::Body => body_text.contains(word),
            MatchScope::Header => response_headers
                .iter()
                .any(|(_, value)| value.to_str().unwrap_or_default().contains(word)),
        })
    }

    async fn match_reverse(
        &self,
        headers: &Vec<String>,
        response_headers: &HeaderMap,
    ) -> Result<bool, ZapError> {
        Ok(headers
            .iter()
            .all(|header| !response_headers.contains_key(header)))
    }

    pub async fn get_or_create_driver(&mut self) -> Result<&WebDriver, Box<dyn Error>> {
        if self.driver.is_none() {
            let mut caps = FirefoxCapabilities::new();
            caps.set_headless()?;
            let driver = WebDriver::new("http://localhost:4444", caps).await?;
            self.driver = Some(driver);
        }
        Ok(self.driver.as_ref().unwrap())
    }

    pub async fn take_web_screenshot(
        &mut self,
        finding_name: &str,
        uri: &str,
        screenshot_path: &Path,
    ) -> Result<(), Box<dyn Error>> {
        let driver = self.get_or_create_driver().await?;
        driver.goto(uri).await?;
        driver.set_window_rect(0, 0, 1920, 1080).await?;
        match driver.screenshot(screenshot_path).await {
            Ok(_) => info!(
                "{}",
                format!(
                    "{} Verified - Screenshot saved to {:?}",
                    finding_name, screenshot_path
                )
                .green()
            ),
            Err(e) => eprintln!("{}", format!("Failed to save screenshot: {:?}", e).red()),
        }
        Ok(())
    }

    pub async fn render_html_screenshot(
        &mut self,
        finding_name: &str,
        html_content: &str,
        screenshot_path: &PathBuf,
    ) -> Result<(), Box<dyn Error>> {
        let mut hasher = Md5::new();
        hasher.update(finding_name.to_lowercase().as_bytes());
        let hash_result = hasher.finalize();
        let identifier = format!("{:x}", hash_result);

        add_html_content(&identifier, html_content.to_string());
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let driver = self.get_or_create_driver().await?;
        let url = format!("http://localhost:10923/screenshot/{}", identifier);
        driver.goto(&url).await?;

        driver.set_window_rect(0, 0, 1920, 1080).await?;
        match driver.screenshot(screenshot_path).await {
            Ok(_) => info!(
                "{}",
                format!(
                    "{} Verified - Screenshot saved to {:?}",
                    finding_name, screenshot_path
                )
                .green()
            ),
            Err(e) => eprintln!("{}", format!("Failed to save screenshot: {:?}", e).red()),
        }
        Ok(())
    }

    fn format_headers_for_screenshot(
        &self,
        finding_name: &str,
        headers: &HeaderMap,
        url: &str,
        match_note: &str,
    ) -> String {
        let header_items = headers
            .iter()
            .map(|(name, value)| {
                format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    name,
                    value.to_str().unwrap_or_default()
                )
            })
            .collect::<Vec<String>>()
            .join("\n");

        let html_content = format!(
            r#"<html>
    <head>
        <style>
            body {{
                font-family: 'Courier New', monospace;
                background-color: #333;
                color: #ccc;
                margin: 20px;
            }}
            a {{
                color: #4DD0E1;
                text-decoration: none;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin-top: 20px;
            }}
            th, td {{
                border: 1px solid #777;
                text-align: left;
                padding: 8px;
            }}
            tr:nth-child(even) {{background-color: #444;}}
            th {{
                background-color: #555;
                color: white;
            }}
        </style>
    </head>
    <body>
        <h1>{finding_name}</h1>
        <div>URL: <a href="{url}" target="_blank">{url}</a></div>
        <div>Match Note: {match_note}</div>
        <table>
            <thead>
                <tr><th>Header</th><th>Value</th></tr>
            </thead>
            <tbody>
                {header_items}
            </tbody>
        </table>
    </body>
    </html>"#,
            finding_name = finding_name,
            url = url,
            header_items = header_items,
            match_note = match_note
        );

        html_content
    }

    fn format_headers_for_report(&self, headers: &HeaderMap) -> String {
        headers
            .iter()
            .map(|(name, value)| {
                format!("\"{}\": \"{}\"", name, value.to_str().unwrap_or_default())
            })
            .collect::<Vec<String>>()
            .join(", ")
    }
}
