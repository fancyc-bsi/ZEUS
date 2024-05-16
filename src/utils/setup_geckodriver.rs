use std::path::Path;
use std::process::{Command, Stdio};

use log::{error, info};

pub fn geckodriver_runner(gecko_driver_path: String) {
    assert!(
        Path::new(&gecko_driver_path).exists(),
        "Geckodriver binary does not exist at the expected path"
    );

    let mut cmd = Command::new(gecko_driver_path);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());

    match cmd.spawn() {
        Ok(_) => info!("Geckodriver started successfully."),
        Err(e) => error!("Failed to start Geckodriver: {}", e),
    }
}
