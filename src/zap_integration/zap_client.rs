use reqwest::Client;
use serde_json::{self, Value};
use std::{fmt, fs};
use std::path::{Path, PathBuf};
use log::error;


#[derive(Debug)]
pub enum ZapError {
    Reqwest(reqwest::Error),
    Serde(serde_json::Error),
    Other(String),
}

impl fmt::Display for ZapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ZapError::Reqwest(ref err) => write!(f, "Reqwest error: {}", err),
            ZapError::Serde(ref err) => write!(f, "Serde error: {}", err),
            ZapError::Other(ref err) => write!(f, "{}", err),
        }
    }
}

impl From<reqwest::Error> for ZapError {
    fn from(err: reqwest::Error) -> ZapError {
        ZapError::Reqwest(err)
    }
}

impl From<serde_json::Error> for ZapError {
    fn from(err: serde_json::Error) -> ZapError {
        ZapError::Serde(err)
    }
}

pub struct ZapClient {
    pub base_url: String,
    client: Client,
}

impl ZapClient {
    pub fn new(base_url: String) -> Self {
        ZapClient {
            base_url,
            client: Client::new(),
        }
    }

    pub async fn get_firefox_binary(&self) -> Result<String, ZapError> {
        let firefox_url = format!("{}/JSON/selenium/view/optionFirefoxDriverPath/", self.base_url);
        
        let response = self.client.get(&firefox_url).send().await?.text().await?;
        let json: serde_json::Value = serde_json::from_str(&response)?;
        
        match json["FirefoxDriverPath"].as_str() {
            Some(path) => Ok(path.to_string()),
            None => Err(ZapError::Other("Failed to get Firefox driver path".to_string()))
        }
    }
    

    pub async fn run_automation_plan(&self, config_path: &str) -> Result<String, ZapError> {
        let absolute_path = fs::canonicalize(Path::new(config_path))
            .map_err(|e| ZapError::Other(format!("Failed to canonicalize path: {}", e)))?
            .to_str()
            .ok_or_else(|| ZapError::Other("Failed to convert path to string.".to_string()))?
            .to_owned();
    
        let run_plan_url = format!("{}/JSON/automation/action/runPlan/?filePath={}", self.base_url, absolute_path);
        
        let resp = self.client.get(&run_plan_url).send().await?.text().await?;
        
        let json: serde_json::Value = serde_json::from_str(&resp)?;
        let plan_id = json.get("planId")
                          .and_then(|v| v.as_str())
                          .map(|s| s.to_string());
    
        match plan_id {
            Some(id) if !id.is_empty() => Ok(id),
            _ => Err(ZapError::Other("Failed to extract plan ID from response.".to_string())),
        }
    }
    

    pub async fn check_plan_progress(&self, plan_id: &str) -> Result<String, ZapError> {
        let progress_url = format!("{}/JSON/automation/view/planProgress/?planId={}", self.base_url, plan_id);
        
        let response = self.client.get(progress_url).send().await?.text().await?;
        
        Ok(response)
    }
    

    pub async fn set_http_proxy(&self, host: &str, port: &str) -> Result<String, ZapError> {
        let set_proxy_url = format!("{}/JSON/network/action/setHttpProxy/?host={}&port={}", self.base_url, host, port);

        self.client.get(&set_proxy_url).send().await?;

        let enable_proxy_url = format!("{}/JSON/network/action/setHttpProxyEnabled/?enabled=true", self.base_url);

        let response = self.client.get(&enable_proxy_url).send().await?.text().await?;

        Ok(response)
    }

    pub async fn flush_http_proxy(&self) -> Result<String, ZapError> {
        let set_proxy_url = format!("{}/JSON/network/action/setHttpProxy/?host={}&port={}", self.base_url, "", "");

        self.client.get(&set_proxy_url).send().await?;

        let disable_proxy_url = format!("{}/JSON/network/action/setHttpProxyEnabled/?enabled=false", self.base_url);

        let response = self.client.get(&disable_proxy_url).send().await?.text().await?;

        Ok(response)
    }

    pub async fn start_ajax_spider(&self, target_url: &str) -> Result<String, ZapError> {
        let ajax_spider_url = format!(
            // "{}/JSON/ajaxSpider/action/scan/?url={}&subtreeOnly=true",
            "{}/JSON/ajaxSpider/action/scan/?url={}",
            self.base_url,
            target_url,
        );
        let response = self.client.get(&ajax_spider_url).send().await
            .map_err(|e| ZapError::Other(format!("Failed to send AJAX Spider request: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(ZapError::Other(format!("AJAX Spider request returned with status: {}", response.status())));
        }
    
        let text = response.text().await
            .map_err(|e| ZapError::Other(format!("Failed to read AJAX Spider response: {}", e)))?;
        
        Ok(text)
    }

    pub async fn check_ajax_spider_status(&self) -> Result<String, ZapError> {
        let status_url = format!("{}/JSON/ajaxSpider/view/status", self.base_url);
        let resp = self.client.get(&status_url).send().await?;
        let text = resp.text().await?;
    
        let json = serde_json::from_str::<Value>(&text)?;
        Ok(json["status"].to_string().trim_matches('"').to_owned())
    }
    
    // pub async fn wait_for_ajax_spider_completion(&self) -> Result<(), ZapError> {
    //     loop {
    //         let status = self.check_ajax_spider_status().await?;
    //         println!("AJAX Spider status: {}", status);
    //         if status == "stopped" {
    //             println!("AJAX Spider has completed.");
    //             break;
    //         }
    //         tokio::time::sleep(Duration::from_secs(5)).await;
    //     }
    //     Ok(())
    // }

    
    pub async fn start_spider(&self, target_url: &str) -> Result<String, ZapError> {
        let spider_scan_url = format!(
            "{}/JSON/spider/action/scan/?url={}&subtreeOnly=true",
            self.base_url, target_url
        );
        let response = self.client.get(&spider_scan_url).send().await?.text().await?;
        Ok(response)
    }
    

    pub async fn spider_status(&self, scan_id: &str) -> Result<String, ZapError> {
        let status_url = format!("{}/JSON/spider/view/status/?scanId={}", self.base_url, scan_id);
        let resp = self.client.get(status_url).send().await?;
        let text = resp.text().await?;
    
        let json = serde_json::from_str::<Value>(&text)?;
        Ok(json["status"].to_string().trim_matches('"').to_owned())
    }

    // pub async fn fetch_all_spider_urls(&self) -> Result<Vec<String>, ZapError> {
    //     let url = format!("{}/JSON/spider/view/allUrls/", self.base_url);
    //     let resp = self.client.get(&url).send().await?;
    //     let text = resp.text().await?;
    //     let json: Value = serde_json::from_str(&text)?;
    
    //     let urls = json["allUrls"]
    //         .as_array()
    //         .unwrap_or(&vec![])
    //         .iter()
    //         .filter_map(|url| url.as_str().map(String::from))
    //         .collect::<Vec<String>>();
    
    //     let mut table = Table::new();
    //     table.add_row(row!["Index", "URL"]);
    //     for (index, url) in urls.iter().enumerate() {
    //         table.add_row(row![index + 1, url]);
    //     }
    
    //     if !urls.is_empty() {
    //         table.printstd();
    //     } else {
    //         println!("No URLs found during spidering.");
    //     }
    
    //     Ok(urls)
    // }

    pub async fn start_scan(&self, target_url: &str) -> Result<String, ZapError> {
     
        let start_scan_url = format!(
            // "{}/JSON/ascan/action/scan/?url={}&recurse=true&inScopeOnly=true",
            "{}/JSON/ascan/action/scan/?url={}",
            self.base_url, target_url
        );
        let resp = self.client.get(&start_scan_url).send().await?;
        let text = resp.text().await?;
        
        let json: Value = serde_json::from_str(&text)?;
        let scan_id = json.get("scan").and_then(Value::as_str).ok_or_else(|| {
            error!("Error: Scan ID not found in response. Response text: {}", text);
            ZapError::Other("Scan ID not found in response".to_string())
        })?;
    
        Ok(scan_id.to_string())
    }
    
    
    

    pub async fn scan_status(&self, scan_id: &str) -> Result<String, ZapError> {
        let status_url = format!("{}/JSON/ascan/view/status/?scanId={}", self.base_url, scan_id);
        let response = self.client.get(status_url).send().await?;
        let text = response.text().await?;
        let json: Value = serde_json::from_str(&text)?;
        let status = json.get("status").and_then(Value::as_str).ok_or_else(|| {
            ZapError::Other("Status not found in response".to_string())
        })?;
        Ok(status.to_string())
    }
    

    pub async fn fetch_json_report(&self) -> Result<String, ZapError> {
        let json_report_url = format!("{}/OTHER/core/other/jsonreport/", self.base_url);
        let resp = self.client.get(&json_report_url).send().await?;
        let text = resp.text().await?;
        Ok(text)
    }

    pub async fn fetch_and_save_json_report(&self, project_folder_path: &PathBuf, report_title: &str, description: &str) -> Result<(), ZapError> {
        let url = format!("{}/JSON/reports/action/generate/", self.base_url);
    
        fs::create_dir_all(project_folder_path).map_err(|e| {
            ZapError::Other(format!("Failed to create directory: {}", e))
        })?;
    
        let absolute_path = fs::canonicalize(project_folder_path).map_err(|e| {
            ZapError::Other(format!("Failed to resolve absolute path: {}", e))
        })?;

    
        let report_filename = "zap_report.json";
        let final_file_path = absolute_path.join(report_filename);
    
        let response = self.client.get(&url)
            .query(&[
                ("title", report_title),
                ("template", "traditional-json-plus"),
                ("description", description),
                ("reportDir", absolute_path.to_str().unwrap()),
                ("reportFileName", report_filename),
                ("display", "false"),
            ])
            .send().await?;
    
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ZapError::Other(format!("Failed to fetch report: HTTP {} - {}", status, text)));
        }
    
        if final_file_path.exists() {
            Ok(())
        } else {
            Err(ZapError::Other("Report file does not exist in the expected location".to_string()))
        }
    }

    pub async fn fetch_and_save_html_report(&self, project_folder_path: &PathBuf, report_title: &str, description: &str) -> Result<(), ZapError> {
        let url = format!("{}/JSON/reports/action/generate/", self.base_url);
    
        fs::create_dir_all(project_folder_path).map_err(|e| {
            ZapError::Other(format!("Failed to create directory: {}", e))
        })?;
    
        let absolute_path = fs::canonicalize(project_folder_path).map_err(|e| {
            ZapError::Other(format!("Failed to resolve absolute path: {}", e))
        })?;

    
        let report_filename = "zap_report.html";
        let final_file_path = absolute_path.join(report_filename);
    
        let response = self.client.get(&url)
            .query(&[
                ("title", report_title),
                ("template", "modern"),
                ("theme", "marketing"),
                ("description", description),
                ("reportDir", absolute_path.to_str().unwrap()),
                ("reportFileName", report_filename),
                ("display", "false"),
            ])
            .send().await?;
    
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ZapError::Other(format!("Failed to fetch report: HTTP {} - {}", status, text)));
        }
    
        if final_file_path.exists() {
            Ok(())
        } else {
            Err(ZapError::Other("Report file does not exist in the expected location".to_string()))
        }
    }

    pub fn extract_scan_id(response: &str) -> Result<String, ZapError> {
        let value: Value = serde_json::from_str(response)?;
        if let Some(scan_id) = value["scan"].as_str() {
            Ok(scan_id.to_string())
        } else {
            Err(ZapError::Other("Scan ID not found".to_string()))
        }
    }
    

    
    // pub async fn fetch_html_report(&self, file_path: &Path) -> Result<(), ZapError> {
    //     let html_report_url = format!("{}/OTHER/core/other/htmlreport/", self.base_url);
    //     let resp = self.client.get(&html_report_url).send().await?;
        
    //     let bytes = resp.bytes().await.map_err(ZapError::from)?;

    //     let mut file = File::create(file_path).map_err(|e: std::io::Error| ZapError::Other(format!("Failed to create file: {}", e)))?;
        
    //     file.write_all(&bytes).map_err(|e| ZapError::Other(format!("Failed to write to file: {}", e)))?;

    //     Ok(())
    // }


    


    // pub async fn set_authentication(&self, context_id: &str, auth_method: &str, auth_parameters: &str) -> Result<String, ZapError> {
    //     let auth_url = format!("{}/JSON/authentication/action/setAuthenticationMethod/?contextId={}&authMethodName={}&authMethodConfigParams={}", 
    //                            self.base_url, context_id, auth_method, auth_parameters);
    //     let response = self.client.get(&auth_url).send().await?.text().await?;
    //     Ok(response)
    // }
    
    // pub async fn set_user(&self, context_id: &str, name: &str, credentials: &str) -> Result<String, ZapError> {
    //     let user_url = format!("{}/JSON/users/action/newUser/?contextId={}&name={}", self.base_url, context_id, name);
    //     let response = self.client.get(&user_url).send().await?.text().await?;
        
    //     let user_id: Value = serde_json::from_str(&response)?;
    //     let user_id = user_id["userId"].to_string().trim_matches('"').to_owned();
        
    //     let set_credentials_url = format!("{}/JSON/users/action/setAuthenticationCredentials/?contextId={}&userId={}&authCredentialsConfigParams={}", 
    //                                        self.base_url, context_id, user_id, credentials);
    //     self.client.get(&set_credentials_url).send().await?.text().await?;
        
    //     Ok(user_id)
    // }
    
    // pub async fn enable_user(&self, context_id: &str, user_id: &str) -> Result<String, ZapError> {
    //     let enable_url = format!("{}/JSON/users/action/setUserEnabled/?contextId={}&userId={}&enabled=true", self.base_url, context_id, user_id);
    //     let response = self.client.get(&enable_url).send().await?.text().await?;
    //     Ok(response)
    // }

    // pub async fn start_scan_as_user(&self, context_id: &str, user_id: &str, target_url: &str) -> Result<String, ZapError> {
    //     let start_scan_url = format!("{}/JSON/ascan/action/scanAsUser/?url={}&contextId={}&userId={}&recurse=true", 
    //                                  self.base_url, target_url, context_id, user_id);
    //     let response = self.client.get(start_scan_url).send().await?.text().await?;
        
    //     let json: Value = serde_json::from_str(&response)?;
    //     let scan_id = json.get("scan").and_then(Value::as_str).ok_or_else(|| 
    //         ZapError::Other("Scan ID not found in response".to_string())
    //     )?;
    //     Ok(scan_id.to_string())
    // }
    
    // pub async fn create_context(&self, context_name: &str) -> Result<String, ZapError> {
    //     let url = format!("{}/JSON/context/action/newContext/?contextName={}", self.base_url, context_name);
    //     let response = self.client.get(&url).send().await?.text().await?;
    //     let json: Value = serde_json::from_str(&response)?;
    //     let context_id = json["contextId"].as_str().ok_or_else(|| ZapError::Other("Context ID not found in response".to_string()))?;
    //     Ok(context_id.to_string())
    // }

    // pub async fn include_in_context(&self, context_name: &str, regex: &str) -> Result<String, ZapError> {
    //     let url = format!("{}/JSON/context/action/includeInContext/?contextName={}&regex={}", self.base_url, context_name, regex);
    //     let response = self.client.get(&url).send().await?.text().await?;
    //     Ok(response)
    // }

    // pub async fn set_form_based_auth(&self, context_id: &str, login_url: &str, login_request_data: &str) -> Result<String, ZapError> {
    //     let auth_method_config_params = format!("loginUrl={},loginRequestData={}", login_url, login_request_data);
    //     self.set_authentication(context_id, "formBasedAuthentication", &auth_method_config_params).await
    // }
    
}
