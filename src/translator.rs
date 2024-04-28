// use reqwest::header::HeaderMap;


// fn escape_header_value(value: &str) -> String {
//     let mut escaped = String::new();
//     for ch in value.chars() {
//         match ch {
//             '"' => escaped.push_str("\\\""),
//             '$' => escaped.push_str("\\$"),
//             '`' => escaped.push_str("\\`"), 
//             '\\' => escaped.push_str("\\\\"),
//             _ => escaped.push(ch),
//         }
//     }
//     escaped
// }

// pub fn generate_curl_command(method: &str, uri: &str, headers: &HeaderMap, proxy_option: Option<&str>) -> String {
//     let headers_str = headers
//         .iter()
//         .map(|(h, v)| {
//             let header_value = v.to_str().unwrap_or_default();
//             let escaped_header_value = escape_header_value(header_value);
//             format!("-H \"{}: {}\"", h, escaped_header_value)
//         })
//         .collect::<Vec<String>>()
//         .join(" ");
    
//     let proxy_str = proxy_option.map(|p| format!("--proxy {}", p)).unwrap_or_default();

//     format!("curl --head -X {} {} {} {}", method.to_uppercase(), headers_str, proxy_str, uri)
// }
