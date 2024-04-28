use crate::results_parser::parser::Finding;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::collections::HashMap;
#[derive(Clone)]
pub struct VerifiedFinding {
    pub finding: Finding,
    pub wstg_category: String,
    pub verified: bool,
    pub request: Option<String>,
    pub response: Option<String>,
    pub match_note: Option<String>,
}

fn severity_to_order(severity: &str) -> u8 {
    match severity {
        "Critical" => 1,
        "High" => 2,
        "Medium" => 3,
        "Low" => 4,
        "Informational" => 5,
        _ => 6,
    }
}



pub fn generate_html_report(verified_findings: &[VerifiedFinding], report_path: &Path) -> std::io::Result<()> {
    let mut file = File::create(report_path)?;

    let mut sorted_findings = verified_findings.to_vec();
    sorted_findings.sort_by_key(|f| severity_to_order(f.finding.riskdesc.split_whitespace().next().unwrap_or("Unknown")));

    let severity_counts = verified_findings.iter().fold(HashMap::new(), |mut acc, finding| {
        let severity_level = finding.finding.riskdesc.split_whitespace().next().unwrap_or("Unknown");
        *acc.entry(severity_level.to_string()).or_insert(0) += 1;
        acc
    });

    // Sort severity counts by defined order
    let mut sorted_severities: Vec<_> = severity_counts.iter().collect();
    sorted_severities.sort_by_key(|&(severity, _)| severity_to_order(severity));


    writeln!(file, "<!DOCTYPE html>")?;
    writeln!(file, "<html lang='en'>")?;
    writeln!(file, "<head>")?;
    writeln!(file, "<meta charset='UTF-8'>")?;
    writeln!(file, "<meta name='viewport' content='width=device-width, initial-scale=1.0'>")?;
    writeln!(file, "<title>Verification Report</title>")?;
    writeln!(file, "<link href='https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap' rel='stylesheet'>")?;
    writeln!(file, "<link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>")?;
    writeln!(file, "<style>")?;
    writeln!(file, "body {{ background-color: #343a40; color: #ffffff; font-family: 'Roboto', sans-serif; }}")?;
    writeln!(file, ".container-fluid {{ padding-top: 20px; }}")?;
    writeln!(file, ".card {{ background-color: #495057; }}")?;
    writeln!(file, ".card-header, .table {{ background-color: #6c757d; }}")?;
    writeln!(file, ".card-title, .card-text, th, td {{ color: #ffffff; }}")?;
    writeln!(file, ".verified-yes {{ color: #28a745; }}")?;
    writeln!(file, ".verified-no {{ color: #dc3545; }}")?;
    writeln!(file, ".severity-informational {{ color: #17a2b8; }}")?; // Informational - Blue
    writeln!(file, ".severity-low {{ color: #28a745; }}")?; // Low - Green
    writeln!(file, ".severity-medium {{ color: #ffc107; }}")?; // Medium - Yellow
    writeln!(file, ".severity-high {{ color: #dc3545; }}")?; // High - Red
    writeln!(file, ".severity-critical {{ color: #6f42c1; }}")?; // Critical - Purple
    writeln!(file, ".toc-item {{ margin-bottom: 10px; }}")?;
    writeln!(file, ":root {{ --primary-color: #007bff; --dark-bg: #343a40; --light-text: #f8f9fa; --dark-text: #343a40; }}")?;
    writeln!(file, "body {{ background-color: var(--dark-bg); color: var(--light-text); }}")?;
    writeln!(file, "a {{ color: var(--primary-color); }}")?;
    writeln!(file, "table {{ background-color: #495057; }}")?;
    writeln!(file, ".card {{ border: 1px solid var(--primary-color); }}")?;
    writeln!(file, ".card-header {{ background-color: var(--primary-color); color: var(--dark-text); }}")?;
    writeln!(file, ".response-section {{ margin-top: 20px; color: #ccc; }}")?;
    writeln!(file, ".response-header, .response-value {{ word-wrap: break-word; color: #ccc; }}")?;
    writeln!(file, ".response-table {{ margin-bottom: 20px; border: 1px solid #777; }}")?;
    writeln!(file, ".response-table th, .response-table td {{ border: 1px solid #777; }}")?;
    writeln!(file, ".response-body {{ white-space: pre-wrap; word-wrap: break-word; background-color: #222; color: #ccc; padding: 10px; border-radius: 5px; }}")?;
    writeln!(file, "h5 {{ color: #4DD0E1; }}")?; 
    writeln!(file, "</style>")?;
    writeln!(file, "</head>")?;
    writeln!(file, "<body>")?;
    writeln!(file, "<div class='container-fluid'>")?;
    writeln!(file, "<h1 class='text-center'>Verification Report</h1>")?;

    writeln!(file, "<h2>Summary by Severity</h2>")?;
    writeln!(file, "<table class='table table-dark'>")?;
    writeln!(file, "<thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>")?;
    for (severity, count) in sorted_severities {
        let severity_class = match severity.as_str() {
            "Informational" => "severity-informational",
            "Low" => "severity-low",
            "Medium" => "severity-medium",
            "High" => "severity-high",
            "Critical" => "severity-critical",
            _ => "",
        };
        writeln!(file, "<tr><td class='{}'>{}</td><td>{}</td></tr>", severity_class, severity, count)?;
    }
    writeln!(file, "</tbody></table>")?;

    writeln!(file, "<h2>Table of Contents</h2>")?;
    writeln!(file, "<div class='list-group'>")?;
    for (i, verified_finding) in sorted_findings.iter().enumerate() {
        let severity = verified_finding.finding.riskdesc.split_whitespace().next().unwrap_or("Unknown");
        writeln!(file, "<a href='#finding{}' class='list-group-item list-group-item-action toc-item'>{}</a>", i, format!("{} - {}", verified_finding.finding.name, severity))?;
    }
    writeln!(file, "</div>")?;
    for (i, verified_finding) in sorted_findings.iter().enumerate() {
        let severity = verified_finding.finding.riskdesc.split_whitespace().next().unwrap_or("Unknown");
        writeln!(file, "<div id='finding{}' class='card my-3'>", i)?;
        writeln!(file, "<div class='card-header'>")?;
        writeln!(file, "<h5 class='card-title'>{}</h5>", verified_finding.finding.name)?;
        if !verified_finding.wstg_category.is_empty() {
            writeln!(file, "<h6>WSTG Category: {}</h6>", verified_finding.wstg_category)?;
        }
        writeln!(file, "</div>")?;
        
        writeln!(file, "<div class='card-body'>")?;
        writeln!(file, "<p class='card-text'><strong>Verified:</strong> <span class='{}'>{}</span></p>", if verified_finding.verified { "verified-yes" } else { "verified-no" }, if verified_finding.verified { "Yes" } else { "No" })?;
        
        let severity_class = match severity {
            "Informational" => "severity-informational",
            "Low" => "severity-low",
            "Medium" => "severity-medium",
            "High" => "severity-high",
            "Critical" => "severity-critical",
            _ => "",
        };
        
        writeln!(file, "<p class='card-text'><strong>Risk:</strong> <span class='{}'>{}</span></p>", severity_class, severity)?;
        writeln!(file, "<p class='card-text'><strong>Description:</strong> {}</p>", verified_finding.finding.desc)?;
        writeln!(file, "<p class='card-text'><strong>Solution:</strong> {}</p>", verified_finding.finding.solution)?;
        let uris_list = verified_finding.finding.uris.iter()
            .map(|uri| format!("<li>{}</li>", uri))
            .collect::<Vec<String>>()
            .join("\n");

        writeln!(file, "<p class='card-text'><strong>Affected Assets:</strong></p><ul>{}</ul>", uris_list)?;
        if let Some(note) = &verified_finding.match_note {
            writeln!(file, "<div class='response-section'>")?;
            writeln!(file, "<h5>Match Note</h5>")?;
            writeln!(file, "<pre class='response-body'>{}</pre>", escape_html(note))?;
            writeln!(file, "</div>")?;
        }
        if let Some(request) = &verified_finding.request {
            writeln!(file, "<h6>Request</h6><pre><code>{}</code></pre>", escape_html(request))?;
        }
        if let Some(response) = &verified_finding.response {
            writeln!(file, "<h6>Response</h6><button class='btn btn-primary mb-2' onclick='toggleResponse(\"response{}\")'>Show Response</button><div id='response{}' style='display:none;'>{}</div>", i, i, format_response(response))?;
        }
        writeln!(file, "</div>")?;
        writeln!(file, "</div>")?;
    }
    writeln!(file, "</div>")?;
    writeln!(file, "<script src='https://code.jquery.com/jquery-3.5.1.slim.min.js'></script>")?;
    writeln!(file, "<script src='https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.2/dist/umd/popper.min.js'></script>")?;
    writeln!(file, "<script src='https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js'></script>")?;
    writeln!(file, "<script>")?;
    writeln!(file, "function toggleResponse(id) {{")?;
    writeln!(file, "  var x = document.getElementById(id);")?;
    writeln!(file, "  if (x.style.display === 'none') {{")?;
    writeln!(file, "    x.style.display = 'block';")?;
    writeln!(file, "  }} else {{")?;
    writeln!(file, "    x.style.display = 'none';")?;
    writeln!(file, "  }}")?;
    writeln!(file, "}}")?;
    writeln!(file, "</script>")?;
    writeln!(file, "</body></html>")?;

    Ok(())
}


fn format_response(response: &str) -> String {
    let (headers_part, body) = response.split_once("\n\n").unwrap_or((response, ""));
    let headers = headers_part.trim_start_matches("headers: ");

    let formatted_headers = headers
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(", ")
        .map(|header| {
            let parts: Vec<&str> = header.splitn(2, ": ").collect();
            format!(
                "<tr><td class='response-header'>{}</td><td class='response-value'>{}</td></tr>",
                escape_html(parts.get(0).unwrap_or(&"").trim_matches('"')),
                escape_html(parts.get(1).unwrap_or(&"").trim_matches('"'))
            )
        })
        .collect::<Vec<String>>()
        .join("\n");

    let headers_table = if !formatted_headers.is_empty() {
        format!(
            "<table class='table response-table'><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>{}</tbody></table>",
            formatted_headers
        )
    } else {
        String::new()
    };

    let escaped_body = escape_html(body);

    format!(
        "<div class='response-section'><h5>Headers</h5>{}</div><div class='response-section'><h5>Body</h5><pre class='response-body'>{}</pre></div>",
        headers_table, escaped_body
    )
}



fn escape_html(input: &str) -> String {
    input.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace("\"", "&quot;")
         .replace("'", "&#39;")
}
