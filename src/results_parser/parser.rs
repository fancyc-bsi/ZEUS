use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use csv::Writer;
use std::error::Error;
use std::fs;
use toml::Value as TomlValue;
use crate::report_generator::html_report::VerifiedFinding;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Alert {
    pub name: String,
    pub riskdesc: String,
    pub desc: String,
    pub solution: String,
    pub reference: String,
    pub instances: Vec<Instance>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Instance {
    uri: String,
}

#[derive(Default, Debug, Clone)]
pub struct Finding {
    pub name: String,
    pub riskdesc: String,
    pub desc: String,
    pub solution: String,
    pub reference: String,
    pub uris: Vec<String>,
}

pub fn apply_severity_overrides(findings: &mut HashMap<String, Finding>, config: &str) -> Result<(), Box<dyn Error>> {
    let config: TomlValue = toml::from_str(config)?;

    for (name, finding) in findings.iter_mut() {
        if let Some(value) = config.get(name) {
            if let Some(severity) = value.get("severity").and_then(|v| v.as_str()) {
                finding.riskdesc = severity.to_string();
            }
        }
    }

    Ok(())
}

pub fn load_config() -> Option<String> {
    let path = Path::new("src/config/severity_config.toml");

    let mut file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(_) => return None,
    };

    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_) => Some(contents),
        Err(_) => None,
    }
}


pub fn parse_json(raw_json: &str) -> Result<HashMap<String, Finding>, Box<dyn Error>> {
    let parsed: Value = serde_json::from_str(raw_json)?;
    let mut findings: HashMap<String, Finding> = HashMap::new();

    if let Some(sites) = parsed["site"].as_array() {
        for site in sites {
            if let Some(alerts) = site["alerts"].as_array() {
                for alert_value in alerts {
                    let alert: Alert = serde_json::from_value(alert_value.clone())?;

                    let finding = findings.entry(alert.name.clone()).or_insert_with(|| Finding {
                        name: alert.name.clone(),
                        riskdesc: alert.riskdesc.clone(),
                        desc: alert.desc.clone(),
                        solution: alert.solution.clone(),
                        reference: alert.reference.clone(),
                        uris: Vec::new(),
                    });

                    for instance in &alert.instances {
                        if !finding.uris.contains(&instance.uri) {
                            finding.uris.push(instance.uri.clone());
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}


pub fn generate_csv_from_verified_findings(findings: &[VerifiedFinding], csv_file_path: &Path) -> Result<(), Box<dyn Error>> {
    let mut wtr = Writer::from_path(csv_file_path)?;

    wtr.write_record(&[
        "Plugin ID", "CVE", "Risk", "Host", "Protocol", "Port", "Name",
        "Description", "Solution", "See Also", "References"
    ])?;
    
    for verified_finding in findings {
        let severity = verified_finding.finding.riskdesc.split_whitespace().next().unwrap_or("Unknown");
        let plugin_id = "";
        let protocol = "";
        let port = "";
        let see_also = "";
        let cve = "";

        if severity.to_lowercase() == "informational" {
            continue;
        }

        wtr.write_record(&[
            plugin_id,
            cve,
            severity,
            &verified_finding.finding.uris.join(", "),
            protocol,
            port,
            &verified_finding.finding.name,
            &verified_finding.finding.desc,
            &verified_finding.finding.solution,
            see_also,
            &verified_finding.finding.reference,
        ])?;
    }


    wtr.flush()?;
    Ok(())
}