use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use warp::Filter;

static HTML_CONTENT_MAP: Lazy<Arc<Mutex<HashMap<String, String>>>> = Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

pub fn add_html_content(id: &str, content: String) {
    let mut lock = HTML_CONTENT_MAP.lock().unwrap();
    lock.insert(id.to_string(), content);
}

pub async fn serve_html() {
    let html_map = HTML_CONTENT_MAP.clone();
    let route = warp::path!("screenshot" / String).map(move |id: String| {
        let lock = html_map.lock().unwrap();
        let html_content = lock.get(&id).cloned().unwrap_or_else(|| "Content not found".to_string());
        warp::reply::html(html_content)
    });

    warp::serve(route).run(([127, 0, 0, 1], 10923)).await;
}