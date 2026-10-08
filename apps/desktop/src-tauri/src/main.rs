#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[cfg(target_os = "macos")]
mod gateway {
    use konsollink_helper::ipc::{Client, Command, ExpectedSample, Status};
    use std::sync::{Arc, Mutex};
    #[derive(Default)]
    pub struct Connection(pub Arc<Mutex<Option<Client>>>);

    #[tauri::command]
    pub async fn gateway_request(
        state: tauri::State<'_, Connection>,
        action: String,
        console: Option<String>,
        ipv4_only: bool,
        exclusive_host: bool,
    ) -> Result<Status, String> {
        let command = match action.as_str() {
            "status" => Command::Status {},
            "stop" => Command::Stop {},
            "sample_non_discord" => Command::BeginSample {
                expected: ExpectedSample::NonDiscord,
            },
            "sample_discord_control" => Command::BeginSample {
                expected: ExpectedSample::DiscordControl,
            },
            "finish_sample" => Command::FinishSample {},
            "reset_qualification" => Command::ResetQualification {},
            "start" => Command::Start {
                console: console
                    .ok_or("Konsol IP adresi gerekli")?
                    .parse()
                    .map_err(|_| "Geçersiz IPv4 adresi")?,
                ipv4_only_confirmed: ipv4_only,
                exclusive_host_confirmed: exclusive_host,
            },
            _ => return Err("Bilinmeyen işlem".into()),
        };
        // Blocking socket work runs off the WebView event loop. One connection
        // owns the session; process death closes it, so helper rolls back.
        let connection = state.0.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let mut client = connection
                .lock()
                .map_err(|_| "Helper bağlantısı kilitlendi")?;
            if client.is_none() {
                *client =
                    Some(Client::connect().map_err(|e| format!("M0 helper bağlantısı yok: {e}"))?);
            }
            match client
                .as_mut()
                .ok_or("Helper bağlantısı yok")?
                .request(command)
            {
                Ok(status) => Ok(status),
                Err(e) => {
                    *client = None;
                    Err(format!(
                        "Helper bağlantısı kesildi; konsol ağ ayarını router’a döndürün: {e}"
                    ))
                }
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
mod gateway {
    use konsollink_platform::deployment::{DeploymentContract, HostPlatform, CONSOLE, GATEWAY};
    use serde::Serialize;
    use std::{process::Command, thread, time::Duration};

    #[derive(Serialize)]
    pub struct Gateway {
        host: String,
        router: String,
        console: String,
    }
    #[derive(Serialize)]
    pub struct Qualification {
        state: &'static str,
        active_sample: Option<String>,
        non_discord_samples: u8,
        discord_control_samples: u8,
    }
    #[derive(Serialize)]
    pub struct Observation {
        state: &'static str,
        captured_packets: u8,
        dropped_packets: u8,
        learned_destinations: u8,
        direct_observations: u8,
        discord_control_candidates: u8,
        discord_media_candidates: u8,
    }
    #[derive(Serialize)]
    pub struct Status {
        version: u8,
        state: &'static str,
        gateway: Option<Gateway>,
        discord_bypass: bool,
        intercepted_destinations: u8,
        qualification: Qualification,
        observation: Observation,
        error: Option<String>,
    }

    #[cfg(target_os = "windows")]
    fn platform() -> HostPlatform {
        HostPlatform::Windows
    }
    #[cfg(target_os = "linux")]
    fn platform() -> HostPlatform {
        HostPlatform::Linux
    }

    #[cfg(target_os = "windows")]
    fn service(action: &str) -> Result<std::process::Output, String> {
        let argument = match action {
            "start" => "start",
            "stop" => "stop",
            _ => "query",
        };
        Command::new(r"C:\Windows\System32\sc.exe")
            .args([argument, "KonsolLink"])
            .output()
            .map_err(|e| format!("Windows hizmet yöneticisi çalışmadı: {e}"))
    }
    #[cfg(target_os = "windows")]
    fn service_snapshot() -> Result<(bool, u32), String> {
        use windows_sys::Win32::{
            Foundation::ERROR_SERVICE_DOES_NOT_EXIST,
            System::Services::{
                CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
                SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
                SERVICE_STATUS_PROCESS,
            },
        };

        // Polling happens every three seconds while the GUI is open. Query the
        // fixed service directly instead of spawning sc.exe for every poll.
        let manager =
            unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            return Err(format!(
                "Windows hizmet yöneticisi açılamadı: {}",
                std::io::Error::last_os_error()
            ));
        }
        let name: Vec<u16> = "KonsolLink\0".encode_utf16().collect();
        let handle = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
        let open_error = std::io::Error::last_os_error();
        unsafe { CloseServiceHandle(manager) };
        if handle.is_null() {
            if open_error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
                return Ok((false, 0));
            }
            return Err(format!("KonsolLink hizmeti açılamadı: {open_error}"));
        }
        let mut state = std::mem::MaybeUninit::<SERVICE_STATUS_PROCESS>::uninit();
        let mut needed = 0;
        let queried = unsafe {
            QueryServiceStatusEx(
                handle,
                SC_STATUS_PROCESS_INFO,
                state.as_mut_ptr().cast(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        };
        let query_error = std::io::Error::last_os_error();
        unsafe { CloseServiceHandle(handle) };
        if queried == 0 {
            return Err(format!("KonsolLink hizmet durumu okunamadı: {query_error}"));
        }
        let state = unsafe { state.assume_init() };
        Ok((state.dwCurrentState == SERVICE_RUNNING, state.dwProcessId))
    }

    #[cfg(target_os = "windows")]
    fn active() -> Result<bool, String> {
        service_snapshot().map(|(running, _)| running)
    }

    #[cfg(target_os = "windows")]
    fn health_error(pid: u32) -> Option<String> {
        use std::{
            io::Read,
            time::{SystemTime, UNIX_EPOCH},
        };
        #[derive(serde::Deserialize)]
        struct Health {
            schema: u32,
            pid: u32,
            checked_unix: u64,
            state: String,
            error: String,
        }
        let unavailable = || {
            Some(
                "Windows ağ kontrolü: güncel motor doğrulaması bekleniyor; hizmet açık.".to_owned(),
            )
        };
        let root = DeploymentContract::for_platform(HostPlatform::Windows)
            .ok()?
            .install_root;
        let file =
            match std::fs::File::open(std::path::Path::new(root).join("diagnostics/status.json")) {
                Ok(file) => file,
                Err(_) => return unavailable(),
            };
        let mut bytes = Vec::new();
        if file.take(4097).read_to_end(&mut bytes).is_err() || bytes.len() > 4096 {
            return unavailable();
        }
        let health: Health = match serde_json::from_slice(&bytes) {
            Ok(health) => health,
            Err(_) => return unavailable(),
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        if health.schema != 1
            || health.pid != pid
            || health.checked_unix > now + 5
            || now.saturating_sub(health.checked_unix) > 120
        {
            return unavailable();
        }
        if health.state == "healthy" && health.error.is_empty() {
            None
        } else if !health.error.is_empty() {
            Some(health.error)
        } else {
            unavailable()
        }
    }

    #[cfg(target_os = "linux")]
    fn service(action: &str) -> Result<std::process::Output, String> {
        let argument = match action {
            "start" => "start",
            "stop" => "stop",
            _ => "is-active",
        };
        Command::new("/usr/bin/systemctl")
            .args([argument, "konsollink.service"])
            .output()
            .map_err(|e| format!("systemd çalışmadı: {e}"))
    }
    #[cfg(target_os = "linux")]
    fn active() -> Result<bool, String> {
        let output = service("status")?;
        Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "active")
    }

    fn status(error: Option<String>) -> Result<Status, String> {
        DeploymentContract::for_platform(platform())?;
        #[cfg(target_os = "windows")]
        let (running, pid) = service_snapshot()?;
        #[cfg(target_os = "linux")]
        let running = active()?;
        #[cfg(target_os = "windows")]
        let error = error.or_else(|| if running { health_error(pid) } else { None });
        Ok(Status {
            version: 4,
            state: if running { "gateway_active" } else { "off" },
            gateway: running.then(|| Gateway {
                host: GATEWAY.to_string(),
                router: GATEWAY.to_string(),
                console: CONSOLE.to_string(),
            }),
            discord_bypass: running && error.is_none(),
            intercepted_destinations: 0,
            qualification: Qualification {
                state: "qualified",
                active_sample: None,
                non_discord_samples: 2,
                discord_control_samples: 1,
            },
            observation: Observation {
                state: if running { "active" } else { "off" },
                captured_packets: 0,
                dropped_packets: 0,
                learned_destinations: 0,
                direct_observations: 0,
                discord_control_candidates: 0,
                discord_media_candidates: 0,
            },
            error,
        })
    }

    #[tauri::command]
    pub async fn gateway_request(
        action: String,
        console: Option<String>,
        ipv4_only: bool,
        exclusive_host: bool,
    ) -> Result<Status, String> {
        tauri::async_runtime::spawn_blocking(move || {
            match action.as_str() {
                "status" => return status(None),
                "start" => {
                    if console.as_deref() != Some("172.24.2.10") || !ipv4_only || !exclusive_host {
                        return Err("Sabit konsol adresi ve iki hazırlık onayı gerekli".into());
                    }
                }
                "stop" => {}
                _ => return Err("Bu platformda kullanılmayan eski tanıma işlemi".into()),
            }
            let output = service(&action)?;
            if !output.status.success() {
                let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                return status(Some(format!(
                    "KonsolLink hizmeti {action} işlemini reddetti: {detail}"
                )));
            }
            for _ in 0..25 {
                let running = active()?;
                if (action == "start" && running) || (action == "stop" && !running) {
                    return status(None);
                }
                thread::sleep(Duration::from_millis(200));
            }
            status(Some(format!(
                "KonsolLink hizmeti {action} zaman aşımına uğradı"
            )))
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

fn main() {
    let builder = tauri::Builder::default();
    #[cfg(target_os = "macos")]
    let builder = builder
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .manage(gateway::Connection::default())
        .invoke_handler(tauri::generate_handler![gateway::gateway_request]);
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    let builder = builder.invoke_handler(tauri::generate_handler![gateway::gateway_request]);
    builder
        .setup(|app| {
            let open = MenuItem::with_id(app, "open", "KonsolLink'i Aç", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Çıkış", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            let mut tray = TrayIconBuilder::new().tooltip("KonsolLink").menu(&menu);
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            let _tray = tray
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => {
                        if let Some(w) = app.get_webview_window("main") {
                            if let Err(error) = w.show().and_then(|()| w.set_focus()) {
                                eprintln!("Could not show the main window: {error}");
                            }
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("KonsolLink failed");
}
