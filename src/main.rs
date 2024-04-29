use clap::{App, Arg};
use env_logger::Builder;
use env_logger::Env;
use report_generator::html_report::VerifiedFinding;
use serde_json::Value;
use tokio;
use log::{info, warn, error};
use reqwest::Client;
use validator::Validator;
use std::io::BufRead;
use std::path::Path;
use std::process;
use std::time::Duration;
use zap_integration::zap_api::run_zap;
use std::fs;
use std::io;
use std::env;
use std::path::PathBuf;
use verification::verifier::Verifier;
use std::collections::HashMap;
use results_parser::parser::{parse_json, generate_csv_from_verified_findings, Finding};
use crate::report_generator::html_report::generate_html_report;
use crate::results_parser::parser::load_config;
use utils::setup_geckodriver::geckodriver_runner;
use utils::setup_warp::serve_html;
use crate::results_parser::parser::apply_severity_overrides;
use indicatif::{ProgressBar, ProgressStyle};
use tempfile::NamedTempFile;
use regex::Regex;
use colored::*;
use chrono;
use std::io::Write;

mod validator;
mod zap_integration;
mod results_parser;
mod report_generator;
mod verification;
mod utils;
mod translator;
#[tokio::main]
async fn main() {
    print_banner();
    initialize_logging();
    let matches = parse_arguments();

    let browser_mode = matches.is_present("BROWSER");
    let target_url = matches.value_of("TARGET_URL").unwrap();
    let project_folder = matches.value_of("PROJECT_FOLDER").unwrap();
    let http_proxy = matches.value_of("HTTP_PROXY");
    let disable_progress_bars = matches.is_present("NO_PROGRESS");
    let login_config_path = matches.value_of("LOGIN_CONFIG");
    let ajax_scan_enabled = matches.is_present("AJAX_SCAN");

    let validator = Validator::new(http_proxy.map(String::from));
    validator.run_validations(http_proxy.unwrap_or(""), target_url, login_config_path).await;
    let project_folder_path = PathBuf::from(&project_folder);
    ensure_project_folder_exists(&project_folder_path);
    spawn_background_tasks(browser_mode, Some(target_url.to_string())).await; 
    wait_for_zap_startup().await;
    let client = Client::new();
    check_zap_api_accessibility(&client).await;
    let zap_client = setup_zap_client(&http_proxy).await;
    let geckodriver_path = zap_client.get_firefox_binary().await.expect("Failed to get Geckodriver path");
    setup_firefox_driver(geckodriver_path).await;

    if let Some(_config_path) = login_config_path {
        run_login_config_plan(&login_config_path, &zap_client, &http_proxy, &project_folder_path, &target_url).await;
    } else {
        let spider_id = start_spider_scan(&zap_client, &target_url).await;
        monitor_spider_scan_progress(&zap_client, &spider_id, disable_progress_bars).await;
    
        if ajax_scan_enabled { 
            let ajax_scan_result = zap_client.start_ajax_spider(&target_url).await;
            match ajax_scan_result {
                Ok(result) => {
                    info!("AJAX Spider started: {}", result);
                    monitor_ajax_spider_progress(&zap_client, disable_progress_bars).await;
                },
                Err(e) => {
                    error!("Error starting AJAX Spider: {}", e);
                    return;
                }
            }
        }
    
        let scan_id = start_active_scan(&zap_client, &target_url).await;
        monitor_active_scan_progress(&zap_client, &scan_id, disable_progress_bars).await;
    }

    if browser_mode {
        info!("ZAP HUD is active. Press 'r!' when ready to continue with the verification process.");
        wait_for_user_input().await;
    }

    let verified_findings = perform_verification_process(&http_proxy, &client, &zap_client, &project_folder_path).await;
    generate_reports(&verified_findings, &project_folder_path, &zap_client).await;

    shutdown_zap(&client).await;
}

async fn spawn_background_tasks(browser_mode: bool, target_url: Option<String>) {
    tokio::spawn(async {
        serve_html().await;
    });
    tokio::spawn(async move {
        run_zap(browser_mode, target_url.as_deref());
    });
}

fn print_banner() {
    println!("{}", r"

    ▒███████▒▓█████  █    ██   ██████ 
    ▒ ▒ ▒ ▄▀░▓█   ▀  ██  ▓██▒▒██    ▒ 
    ░ ▒ ▄▀▒░ ▒███   ▓██  ▒██░░ ▓██▄   
      ▄▀▒   ░▒▓█  ▄ ▓▓█  ░██░  ▒   ██▒
    ▒███████▒░▒████▒▒▒█████▓ ▒██████▒▒
    ░▒▒ ▓░▒░▒░░ ▒░ ░░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░
    ░░▒ ▒ ░ ▒ ░ ░  ░░░▒░ ░ ░ ░ ░▒  ░ ░
    ░ ░ ░ ░ ░   ░    ░░░ ░ ░ ░  ░  ░  
      ░ ░       ░  ░   ░           ░  
    ░                                 
".cyan());
    println!("{}", "    Advanced webapp scanner backed by ZAP".purple());
    println!();
}

async fn wait_for_user_input() {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    println!("{}", "Please press 'r!' and then ENTER when you are ready to continue with the verification process.".green().bold());

    while let Some(Ok(line)) = lines.next() {
        if line.trim() == "r!" {
            break;
        } else {
            println!("{}", "Invalid input. Press 'r!' followed by ENTER to proceed.".red());
        }
    }
}

async fn setup_firefox_driver(geckodriver_path: String) {
    tokio::spawn(async {
        geckodriver_runner(geckodriver_path)
    });
}

async fn wait_for_zap_startup() {
    tokio::time::sleep(Duration::from_secs(3)).await;
}

fn create_progress_bar(disable_progress_bars: bool, message: String) -> Option<ProgressBar> {
    if !disable_progress_bars {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}"));
        pb.enable_steady_tick(120);
        pb.set_message(message);
        Some(pb)
    } else {
        None
    }
}

fn finish_progress_bar(pb: &Option<ProgressBar>, message: String) {
    if let Some(pb) = pb.as_ref() {
        pb.finish_with_message(message);
    }
}

async fn check_zap_api_accessibility(client: &Client) {
    let base_url = "http://localhost:8080";
    let health_check_url = format!("{}/JSON/", base_url);
    loop {
        match client.get(&health_check_url).send().await {
            Ok(response) if response.status().is_success() => {
                info!("ZAP API is now accessible.");
                break;
            },
            _ => {
                info!("Waiting for ZAP API to become accessible...");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn monitor_ajax_spider_progress(zap_client: &zap_integration::zap_client::ZapClient, disable_progress_bars: bool) {
    if disable_progress_bars {
        return;  // If progress bars are disabled, return immediately
    }

    let ajax_pb = create_progress_bar(false, "AJAX Spider in progress...".to_owned());
    loop {
        match zap_client.check_ajax_spider_status().await {
            Ok(status) => {
                if status == "stopped" || status == "100" {
                    finish_progress_bar(&ajax_pb, "✓ AJAX Spider completed.".to_owned());
                    break;
                }
            },
            Err(e) => {
                println!("Error checking AJAX Spider status: {}", e);
                finish_progress_bar(&ajax_pb, "Error in AJAX Spider.".to_owned());
                break;
            },
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn setup_zap_client(http_proxy: &Option<&str>) -> zap_integration::zap_client::ZapClient {
    let zap_client = zap_integration::zap_client::ZapClient::new("http://localhost:8080".to_string());
    if let Some(proxy) = http_proxy {
        if let Some((host, port)) = proxy.split_once(':') {
            zap_client.set_http_proxy(host, port).await.expect("Failed to set HTTP proxy");
            info!("Configured HTTP proxy: {}:{}", host, port);
        } else {
            error!("Invalid proxy format. Expected format is host:port.");
        }
    } else {
        zap_client.flush_http_proxy().await.expect("Failed to reset HTTP proxy configuration");
        info!("Reset HTTP proxy configuration to default.");
    }
    zap_client
}

async fn run_login_config_plan(login_config_path: &Option<&str>, _zap_client: &zap_integration::zap_client::ZapClient, http_proxy: &Option<&str>, project_folder_path: &PathBuf, target_url: &str) {
    if let Some(config_path) = login_config_path {
        run_zap_automation_plan(config_path, http_proxy, project_folder_path, target_url).await;
    }
}

async fn start_spider_scan(zap_client: &zap_integration::zap_client::ZapClient, target_url: &str) -> String {
    info!("Starting spider crawl ...");
    match zap_client.start_spider(target_url).await {
        Ok(response) => {
            zap_integration::zap_client::ZapClient::extract_scan_id(&response).expect("Failed to extract spider scan ID")
        },
        Err(e) => {
            error!("Error starting spider scan: {}", e);
            "".to_string()
        }
    }
}

async fn monitor_spider_scan_progress(zap_client: &zap_integration::zap_client::ZapClient, spider_id: &str, disable_progress_bars: bool) {
    if !spider_id.is_empty() {
        let spider_pb = create_progress_bar(disable_progress_bars, "Initiating spider scan...".to_owned());
        loop {
            let status = zap_client.spider_status(spider_id).await.expect("Failed to get spider scan status");
            if status == "100" {
                finish_progress_bar(&spider_pb, "✓ Spider scan completed.".to_owned());
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}

async fn start_active_scan(zap_client: &zap_integration::zap_client::ZapClient, target_url: &str) -> String {
    info!("Starting active scan ...");
    match zap_client.start_scan(target_url).await {
        Ok(scan_id) => scan_id,
        Err(e) => {
            error!("Error starting active scan: {}", e);
            "".to_string()
        }
    }
}

async fn monitor_active_scan_progress(zap_client: &zap_integration::zap_client::ZapClient, scan_id: &str, disable_progress_bars: bool) {
    if !scan_id.is_empty() {
        let active_scan_pb = create_progress_bar(disable_progress_bars, "Active scan in progress...".to_owned());
        loop {
            let status = zap_client.scan_status(scan_id).await.expect("Failed to get active scan status");
            if status == "100" {
                finish_progress_bar(&active_scan_pb, "✓ Active scan completed.".to_owned());
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}

async fn perform_verification_process(http_proxy: &Option<&str>, client: &Client, zap_client: &zap_integration::zap_client::ZapClient, project_folder_path: &PathBuf) -> Vec<VerifiedFinding> {
    info!("Starting verification process");
    let verifier_result = Verifier::new(*http_proxy);
    let mut verifier = match verifier_result {
        Ok(verifier) => verifier,
        Err(e) => {
            error!("Failed to create Verifier: {}", e);
            return Vec::new();
        }
    };
    let json_report = zap_client.fetch_json_report().await.expect("Failed to fetch JSON report");
    let mut findings = parse_json(&json_report).expect("Failed to parse JSON report");
    if let Some(config_str) = load_config() {
        apply_severity_overrides(&mut findings, &config_str).expect("Failed to apply severity overrides");
    }
    verify_findings(&mut verifier, &client, findings, project_folder_path.clone()).await
}

async fn _generate_final_reports(verified_findings: &Vec<VerifiedFinding>, project_folder_path: &PathBuf, _zap_client: &zap_integration::zap_client::ZapClient) {
    let final_html_report_path = project_folder_path.join("final_verification_report.html");

    if let Err(e) = generate_html_report(verified_findings, &final_html_report_path) {
        error!("Failed to generate HTML report: {}", e);
    } else {
        info!("Final HTML verification report generated at {:?}", final_html_report_path);
    }

    let csv_file_path = project_folder_path.join("scan_results.csv");
    generate_csv_from_verified_findings(verified_findings, &csv_file_path).expect("Failed to generate CSV");
    info!("CSV report generated at {:?}", csv_file_path);
}


async fn generate_reports(verified_findings: &Vec<VerifiedFinding>, project_folder_path: &PathBuf, zap_client: &zap_integration::zap_client::ZapClient) {
    let final_html_report_path = project_folder_path.join("final_verification_report.html");
    let zap_json_report_path = project_folder_path;
    let zap_html_plus_report_path = project_folder_path;

    if let Err(e) = generate_html_report(verified_findings, &final_html_report_path) {
        error!("Failed to generate HTML report: {}", e);
    } else {
        info!("Final HTML verification report generated at {:?}", final_html_report_path);
    }

    let csv_file_path = project_folder_path.join("scan_results.csv");
    generate_csv_from_verified_findings(verified_findings, &csv_file_path).expect("Failed to generate CSV");
    info!("CSV report generated at {:?}", csv_file_path);

    if let Err(e) = zap_client.fetch_and_save_html_report(&zap_html_plus_report_path, "Comprehensive Report", "ZAP Scan Report").await {
        error!("Failed to fetch ZAP HTML plus report: {}", e);
    } else {
        info!("ZAP HTML plus report successfully saved to {:?}", zap_json_report_path);
    }
    if let Err(e) = zap_client.fetch_and_save_json_report(&zap_json_report_path, "traditional-json-plus", "JsonPlusReport").await {
        error!("Failed to fetch ZAP JSON report: {}", e);
    } else {
        info!("ZAP JSON report successfully saved to {:?}", zap_json_report_path);
    }
}



async fn shutdown_zap(client: &Client) {
    let base_url = "http://localhost:8080";
    let shutdown_url = format!("{}/JSON/core/action/shutdown", base_url);
    match client.get(&shutdown_url).send().await {
        Ok(response) if response.status().is_success() => {
            info!("ZAP is shutting down...");
        },
        _ => {
            error!("Failed to shutdown ZAP.");
        }
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    info!("Shutdown process completed.");
    process::exit(0);
}


fn initialize_logging() {
    let mut builder = Builder::from_env(Env::default().default_filter_or("info"));
    builder.format(|buf, record| {
        let level = record.level();
        let target = record.target();

        let level_colored = match level {
            log::Level::Error => level.to_string().red(),
            log::Level::Warn => level.to_string().yellow(),
            log::Level::Info => level.to_string().green(),
            log::Level::Debug => level.to_string().cyan(),
            log::Level::Trace => level.to_string().magenta(),
        };

        writeln!(
            buf,
            "[{} {} {}] {}",
            chrono::Local::now().format("%H:%M:%S"),
            level_colored,
            target,
            record.args()
        )
    }).init();
}

fn parse_arguments() -> clap::ArgMatches {
    App::new("ZEUS")
        .version("0.1.0")
        .author("Connor Fancy")
        .about("Advanced webapp scanner backed by ZAP")
        .arg(Arg::with_name("TARGET_URL")
            .help("Sets the target URL to scan")
            .required(true)
            .index(1))
        .arg(Arg::with_name("PROJECT_FOLDER")
            .help("The directory where scan data will be saved")
            .required(true)
            .long("project-folder")
            .takes_value(true))
        .arg(Arg::with_name("HTTP_PROXY")
            .help("HTTP proxy in the format host:port")
            .long("proxy")
            .takes_value(true)) 
        .arg(Arg::with_name("NO_PROGRESS")
            .help("Disables progress bars")
            .long("no-progress")
            .takes_value(false))
        .arg(Arg::with_name("LOGIN_CONFIG")
            .long("policy")
            .help("Path to the login configuration YAML file for ZAP")
            .takes_value(true))
        .arg(Arg::with_name("BROWSER")
            .help("Launches ZAP in browser mode with HUD")
            .long("browser")
            .takes_value(false))
        .arg(Arg::with_name("AJAX_SCAN") 
            .help("Enables AJAX scanning for JS heavy apps - MUCH slower and more resource intense")
            .long("ajax-scan")
            .takes_value(false))
        .get_matches()
}


fn ensure_project_folder_exists(project_folder_path: &PathBuf) {
    if !project_folder_path.exists() {
        fs::create_dir_all(project_folder_path).map_err(|e| {
            error!("Failed to create project directory: {}", e);
            io::Error::new(io::ErrorKind::Other, "Failed to create project directory")
        }).expect("Project directory creation failed");
    }
}


async fn run_zap_automation_plan(config_path: &str, _http_proxy: &Option<&str>, project_folder_path: &PathBuf, target_url: &str) {
    let config_str = match fs::read_to_string(config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to read configuration file: {}", e);
            return;
        },
    };

    let modified_config = replace_placeholders(&config_str, project_folder_path.to_str().unwrap(), target_url);

    let temp_file = match NamedTempFile::new() {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to create a temporary file: {}", e);
            return;
        },
    };

    if let Err(e) = fs::write(temp_file.path(), &modified_config) {
        error!("Failed to write modified configuration to temporary file: {}", e);
        return;
    }

    let zap_client = zap_integration::zap_client::ZapClient::new("http://localhost:8080".to_string());

    match zap_client.run_automation_plan(temp_file.path().to_str().unwrap()).await {
        Ok(plan_id) => {
            info!("Automation plan started successfully with plan ID: {}", plan_id);
            wait_for_automation_plan_to_finish(&zap_client, &plan_id).await;
            // let client = Client::new();
            // let verified_findings = perform_verification_process(http_proxy, &client, &zap_client, project_folder_path).await;
            // generate_final_reports(&verified_findings, project_folder_path, &zap_client).await;
        },
        Err(e) => error!("Failed to start automation plan: {}", e),
    }
}


async fn wait_for_automation_plan_to_finish(zap_client: &zap_integration::zap_client::ZapClient, plan_id: &str) {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} Waiting for automation plan to finish..."));

    info!("Waiting for automation plan to finish. Plan ID: {}", plan_id);
    let mut finished = false;
    let mut last_progress = String::new();

    spinner.enable_steady_tick(100);

    while !finished {
        match zap_client.check_plan_progress(plan_id).await {
            Ok(progress_json) => {
                if progress_json.contains("\"finished\":") && !progress_json.contains("\"finished\":\"\"") {
                    last_progress = progress_json.clone();
                    finished = true;
                }
            },
            Err(e) => {
                error!("Failed to check automation plan progress: {}", e);
            },
        }
        if !finished {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    spinner.finish_with_message("Automation plan completed.");
    if !last_progress.is_empty() {
        let final_progress: Value = serde_json::from_str(&last_progress).unwrap();
        display_job_summary(&final_progress);
    }
}

fn display_job_summary(progress: &Value) {
    let mut job_details = HashMap::new();
    process_job_messages(&progress["info"], &mut job_details, "info");
    process_job_messages(&progress["warn"], &mut job_details, "warn");
    process_job_messages(&progress["error"], &mut job_details, "error");

    println!("{}", "Job Summary:".bold().underline());
    println!("------------");

    for (job_name, details) in job_details {
        println!("{}: {}", "Job Name".bold(), job_name);
        for detail in details {
            match detail.split(':').next().unwrap_or_default() {
                "info" => println!(" - {}", detail.green()),
                "warn" => println!(" - {}", detail.yellow()),
                "error" => println!(" - {}", detail.red()),
                _ => println!(" - {}", detail),
            }
        }
        println!("------------");
    }
}

fn process_job_messages(messages: &Value, job_details: &mut HashMap<String, Vec<String>>, category: &str) {
    if let Some(msgs) = messages.as_array() {
        for msg in msgs {
            let message = msg.as_str().unwrap_or_default();
            let job_name = message.split_whitespace().nth(1).unwrap_or_default();
            job_details.entry(job_name.to_string()).or_insert_with(Vec::new).push(format!("{}: {}", category, message));
        }
    }
}



fn replace_placeholders(config: &str, project_folder_path: &str, target_url: &str) -> String {
    let re_report_dir = Regex::new(r"\{\{reportDir\}\}").unwrap();
    let re_base_url = Regex::new(r"\{\{baseURL\}\}").unwrap();

    let absolute_path = Path::new(project_folder_path);
    let absolute_path = if absolute_path.is_absolute() {
        absolute_path.to_path_buf()
    } else {
        env::current_dir().unwrap().join(project_folder_path)
    };

    let config_updated = re_report_dir.replace_all(config, absolute_path.to_str().unwrap()).into_owned();


    let final_config = re_base_url.replace_all(&config_updated, target_url).into_owned();

    final_config
}

async fn verify_findings(verifier: &mut Verifier, _client: &Client, findings: HashMap<String, Finding>, project_folder_path: PathBuf) -> Vec<VerifiedFinding> {
    let mut verified_findings = Vec::new();
    for finding in findings.values() {
        let verification_result = verifier.verify(finding, &project_folder_path).await;

        let wstg_category = verifier.config.findings.iter()
            .find(|f| f.name == finding.name)
            .map(|fc| fc.wstg_category.clone().unwrap_or_else(|| String::from("WSTG Category Not Found")));

        let wstg_category_unwrapped = wstg_category.unwrap_or_else(|| String::from("WSTG Category Not Found")); // Unwrap here

        if let Ok(verified) = verification_result {
            verified_findings.push(VerifiedFinding {
                finding: finding.clone(),
                wstg_category: wstg_category_unwrapped,
                verified: verified.verified,
                request: verified.request,
                response: verified.response,
                match_note: verified.match_note,
            });
        } else {
            warn!("Verification failed for finding: {}", finding.name);
            verified_findings.push(VerifiedFinding {
                finding: finding.clone(),
                wstg_category: wstg_category_unwrapped,
                verified: false,
                request: None,
                response: None,
                match_note: None,
            });
        }
    }
    verified_findings
}
