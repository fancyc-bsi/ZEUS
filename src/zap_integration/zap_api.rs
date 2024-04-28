use std::process::{Command, Stdio, exit};
use std::env;
use std::path::PathBuf;
use std::fs;
use log::{info, error};

pub fn run_zap(hud_mode: bool, target_url: Option<&str>) {
    let zap_dir = PathBuf::from(env::current_dir().unwrap()).join("src/ZAP");

    if !zap_dir.exists() {
        error!("ZAP directory does not exist");
        exit(1);
    }

    let zap_executable_name = if cfg!(target_os = "windows") {
        "zap.bat"
    } else {
        "zap.sh"
    };

    let zap_executable_path = zap_dir.join(zap_executable_name);

    if !zap_executable_path.exists() {
        error!("ZAP executable does not exist");
        exit(1);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&zap_executable_path).expect("Failed to fetch metadata for ZAP executable");
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755); 
        fs::set_permissions(&zap_executable_path, permissions).expect("Failed to set permissions for ZAP executable");
    }

    info!("ZAP API is starting ...");

    let mut command = Command::new(zap_executable_path);
    command.arg("-daemon")
           .arg("-config")
           .arg("api.disablekey=true");

    if hud_mode {
        if let Some(url) = target_url {
            command.arg("-hudurl").arg(url);
        }
    }

    let status = command.stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .current_dir(&zap_dir)
                        .status()
                        .expect("Failed to execute ZAP");

    if !status.success() {
        error!("Failed to run ZAP, process exited with status: {}", status);
        exit(1);
    }
}