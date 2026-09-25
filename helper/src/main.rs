use konsollink_core::{BridgeController, ConsoleDevice, ConsoleFamily, RuntimeConfig};
use konsollink_platform::{preflight, DryRunBackend, NetworkBackend};
use std::{env, error::Error, net::IpAddr, process::ExitCode};

fn usage() {
    eprintln!("konsollink-helper serve --uid <uid> | recover (macOS root)");
    eprintln!("konsollink-helper status | stop | gateway <ipv4> --ipv4-only --exclusive-host");
    eprintln!("konsollink-helper dry-run <playstation|xbox> <ip>");
    eprintln!("konsollink-helper preflight [--console <ipv4>]");
    eprintln!("konsollink-helper journal-status (macOS, root; no network changes)");
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    #[cfg(target_os = "macos")]
    match args.get(1).map(String::as_str) {
        Some("__engine-child") if args.len() == 3 => {
            konsollink_helper::engine::macos::child_main(&args[2])?;
            return Ok(());
        }
        Some("serve") if args.len() == 4 && args[2] == "--uid" => {
            return konsollink_helper::ipc::serve(args[3].parse()?);
        }
        Some("recover") if args.len() == 2 => {
            konsollink_helper::ipc::recover()?;
            println!(
                "{}",
                serde_json::json!({"state":"off", "recovery_complete":true})
            );
            return Ok(());
        }
        Some("status" | "stop") if args.len() == 2 => {
            use konsollink_helper::ipc::{Client, Command};
            let command = if args[1] == "stop" {
                Command::Stop {}
            } else {
                Command::Status {}
            };
            let response = Client::connect()?.request(command)?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            if response.error.is_some() {
                return Err("helper rejected request".into());
            }
            return Ok(());
        }
        Some("gateway")
            if args.len() == 5 && args[3] == "--ipv4-only" && args[4] == "--exclusive-host" =>
        {
            use konsollink_helper::ipc::{Client, Command};
            let mut client = Client::connect()?;
            let response = client.request(Command::Start {
                console: args[2].parse()?,
                ipv4_only_confirmed: true,
                exclusive_host_confirmed: true,
            })?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            if response.error.is_some() {
                return Err("gateway start rejected".into());
            }
            eprintln!("M0 IPv4 gateway trial; Discord bypass is OFF. Keep this terminal open. Ctrl-C disconnects and rolls back.");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let response = client.request(Command::Heartbeat {})?;
                if response.state != "gateway_active" || response.error.is_some() {
                    println!("{}", serde_json::to_string_pretty(&response)?);
                    return Err("gateway lease ended; restore console gateway to router".into());
                }
            }
        }
        _ => {}
    }
    if args.get(1).map(String::as_str) == Some("journal-status") {
        if args.len() != 2 {
            return Err("journal-status accepts no arguments or custom paths".into());
        }
        #[cfg(target_os = "macos")]
        {
            use konsollink_helper::journal::{Phase, Store};
            let store = Store::open_system()?;
            let journal = store.load()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "mode": "journal-status",
                    "network_changed": false,
                    "recovery_required": journal.as_ref().is_some_and(|j| j.phase != Phase::Complete),
                    "journal": journal
                }))?
            );
            return Ok(());
        }
        #[cfg(not(target_os = "macos"))]
        return Err("system journal is only qualified for macOS".into());
    }
    if args.get(1).map(String::as_str) == Some("preflight") {
        let console = match args.len() {
            2 => None,
            4 if args[2] == "--console" => Some(args[3].parse::<std::net::Ipv4Addr>()?),
            _ => return Err("expected preflight [--console <ipv4>]".into()),
        };
        let report = preflight::collect(console)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args.len() != 4 || args[1] != "dry-run" {
        usage();
        return Err(
            "expected dry-run <playstation|xbox> <ip> or preflight [--console <ipv4>]".into(),
        );
    }

    let family = match args[2].as_str() {
        "playstation" => ConsoleFamily::PlayStation,
        "xbox" => ConsoleFamily::Xbox,
        _ => return Err("console must be playstation or xbox".into()),
    };
    let ip: IpAddr = args[3].parse()?;

    let device = ConsoleDevice {
        id: format!("manual-{ip}"),
        display_name: format!("{:?}", family),
        family,
        ip,
        mac: None,
    };

    let mut controller = BridgeController::new(RuntimeConfig::discord_tr()?);
    controller.select_console(device.clone());
    controller.begin_start()?;
    let mut backend = DryRunBackend::new();

    backend.snapshot()?;
    // This backend never mutates the OS. Real transaction/recovery belongs to M0.
    let result = (|| -> Result<(), Box<dyn Error>> {
        backend.enable_gateway(&device)?;
        backend.enable_service_bypass(&controller.config().service)?;
        backend.healthcheck()?;
        controller.mark_started()?;
        controller.begin_stop()?;
        Ok(())
    })();
    // Always attempt cleanup, including on a failed simulated start.
    let restored = backend.restore();
    if let Err(error) = result {
        if let Err(restore_error) = restored {
            return Err(format!("{error}; cleanup also failed: {restore_error}").into());
        }
        return Err(error);
    }
    restored?;
    controller.mark_stopped()?;

    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "state": format!("{:?}", controller.state()),
            "console": device.display_name,
            "ip": device.ip.to_string(),
            "mode": "dry-run"
        })
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "ok": false,
                    "mode": match env::args().nth(1).as_deref() {
                        Some("preflight") => "preflight",
                        Some("journal-status") => "journal-status",
                        Some("dry-run") => "dry-run",
                        _ => "cli"
                    },
                    "error": error.to_string()
                })
            );
            ExitCode::FAILURE
        }
    }
}
