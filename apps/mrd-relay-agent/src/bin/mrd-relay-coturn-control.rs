use std::process::ExitCode;

#[cfg(not(target_os = "linux"))]
use std::path::PathBuf;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
        let socket_activated = arguments == ["--socket-activated"];
        let wsl_broker = arguments
            .first()
            .is_some_and(|value| value == "--wsl-broker");
        if !socket_activated && !wsl_broker {
            eprintln!("relay_broker_cli_invalid");
            return ExitCode::from(64);
        }
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => {
                eprintln!("relay_broker_io_failed");
                return ExitCode::from(70);
            }
        };
        let result = if socket_activated {
            runtime.block_on(mrd_relay_agent::broker::run_linux_socket_activated())
        } else {
            runtime.block_on(mrd_relay_agent::broker::run_linux_wsl_broker(
                arguments[1..].to_vec(),
            ))
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(mrd_relay_agent::broker::BrokerRuntimeError::CliInvalid) => {
                eprintln!("relay_broker_cli_invalid");
                ExitCode::from(64)
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(70)
            }
        }
    }
    #[cfg(windows)]
    {
        let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
        if arguments.len() != 3
            || arguments.first().and_then(|value| value.to_str()) != Some("broker")
            || arguments.get(1).and_then(|value| value.to_str()) != Some("--config")
        {
            eprintln!("relay_broker_cli_invalid");
            return ExitCode::from(64);
        }
        let config = PathBuf::from(&arguments[2]);
        match mrd_relay_agent::broker::run_windows_service(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(70)
            }
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = PathBuf::new();
        eprintln!("relay_broker_platform_unavailable");
        ExitCode::from(69)
    }
}
