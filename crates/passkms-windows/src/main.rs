// COM code is inherently unsafe
#![allow(unsafe_code)]
#![windows_subsystem = "windows"]

//! passkms-windows: Out-of-process COM server for the Windows WebAuthn Plugin API.
//!
//! This binary registers as a COM server and responds to IPluginAuthenticator
//! calls from the Windows WebAuthn platform. It bridges to `passkms-core` for
//! all FIDO2 authenticator logic and KMS interaction.
//!
//! ## Modes
//!
//! - **Default (no args)**: Auto-register plugin if needed, sync credentials, enter COM server loop.
//! - **`-PluginActivated`**: COM activation mode. Windows passes this arg when launching for a
//!   WebAuthn operation. Goes directly into COM server loop (no registration/sync).
//! - **`--unregister`**: Remove plugin registration from Windows and exit.

use std::sync::Arc;

use windows::core::IUnknown;
use windows::Win32::System::Com::{
    CoInitializeEx, CoRegisterClassObject, CoResumeClassObjects, CoRevokeClassObject,
    CoUninitialize, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, REGCLS_MULTIPLEUSE,
    REGCLS_SUSPENDED,
};

mod bindings;
mod com_factory;
mod com_plugin;
mod registration;
mod util;

use com_factory::{PasskeyClassFactory, PASSKEY_CLSID};

/// Execution mode determined from command-line arguments.
enum Mode {
    /// Windows COM activation (launched by the platform for a WebAuthn operation).
    PluginActivated,
    /// Default startup: register if needed, sync credentials, then serve COM.
    Default,
    /// Remove plugin registration and exit.
    Unregister,
}

fn parse_mode() -> Mode {
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-PluginActivated" => return Mode::PluginActivated,
            "--unregister" => return Mode::Unregister,
            other => {
                tracing::warn!(arg = other, "unknown argument, ignoring");
            }
        }
    }
    Mode::Default
}

fn setup_logging() {
    use std::sync::Mutex;
    use tracing_subscriber::prelude::*;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug,aws_config=warn,aws_smithy_runtime=warn,aws_smithy_http_client=warn,aws_sdk_kms=warn,hyper_util=warn,h2=warn"));

    // Write logs to %LOCALAPPDATA%\passkms\passkms.log so they're visible
    // even during COM-activated launches with no console attached.
    let log_dir = std::env::var("LOCALAPPDATA")
        .map(|d| std::path::PathBuf::from(d).join("passkms"))
        .unwrap_or_else(|_| std::env::temp_dir().join("passkms"));

    std::fs::create_dir_all(&log_dir).ok();
    let log_path = log_dir.join("passkms.log");

    let file_layer = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok()
        .map(|file| {
            tracing_subscriber::fmt::layer()
                .with_writer(Mutex::new(file))
                .with_ansi(false)
        });

    let stderr_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(stderr_layer)
        .init();

    tracing::debug!(
        log_file = %log_path.display(),
        "logging initialized"
    );
}

fn main() {
    setup_logging();

    tracing::info!(
        pid = std::process::id(),
        args = ?std::env::args().collect::<Vec<_>>(),
        "passkms-windows starting"
    );

    match parse_mode() {
        Mode::Unregister => {
            tracing::info!("unregistering plugin");
            if let Err(hr) = registration::unregister() {
                tracing::error!(?hr, "unregistration failed");
                std::process::exit(1);
            }
            tracing::info!("plugin unregistered");
        }
        Mode::Default => {
            tracing::info!("default mode: ensuring registration and syncing credentials");

            tracing::debug!("building tokio runtime");
            let runtime = Arc::new(build_runtime());
            let authenticator = Arc::new(build_authenticator(&runtime));

            // Ensure plugin is registered with Windows WebAuthn
            tracing::debug!("checking plugin registration state");
            if let Err(hr) = registration::ensure_registered() {
                tracing::error!(?hr, "plugin registration failed");
                // Continue anyway -- COM server can still work for already-registered state
            }

            // Sync credentials from KMS to Windows passkey picker
            tracing::debug!("starting credential sync from KMS");
            if let Err(e) = registration::sync_credentials(&runtime, authenticator.store()) {
                tracing::warn!(error = %e, "credential sync failed, continuing");
            }

            tracing::debug!("entering COM server loop");
            run_com_server(runtime, authenticator);
        }
        Mode::PluginActivated => {
            tracing::info!("COM activation mode (-PluginActivated)");
            tracing::debug!("building tokio runtime");
            let runtime = Arc::new(build_runtime());
            let authenticator = Arc::new(build_authenticator(&runtime));
            tracing::debug!("entering COM server loop");
            run_com_server(runtime, authenticator);
        }
    }
}

fn build_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

/// Build the passkms-core Authenticator, loading AWS config from the environment.
fn build_authenticator(runtime: &tokio::runtime::Runtime) -> passkms_core::Authenticator {
    runtime.block_on(async {
        tracing::debug!("loading AWS config");
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        tracing::debug!(region = ?config.region(), "AWS config loaded");
        let kms_client = aws_sdk_kms::Client::new(&config);
        let store = passkms_core::CredentialStore::new(kms_client);
        passkms_core::Authenticator::new(store)
    })
}

/// Register COM class factory and run the message loop.
fn run_com_server(runtime: Arc<tokio::runtime::Runtime>, authenticator: Arc<passkms_core::Authenticator>) {
    // SAFETY: COM API calls require unsafe. We ensure correct sequencing:
    // CoInitializeEx before any COM calls, CoRevokeClassObject + CoUninitialize
    // on shutdown. Called on the main thread which owns the message loop.
    unsafe {
        // Initialize COM for multi-threaded apartment
        tracing::debug!("initializing COM (COINIT_MULTITHREADED)");
        CoInitializeEx(None, COINIT_MULTITHREADED)
            .ok()
            .expect("CoInitializeEx failed");

        // Create and register our class factory
        tracing::debug!("creating PasskeyClassFactory");
        let factory = PasskeyClassFactory::new(runtime, authenticator);
        let factory_unknown: IUnknown = factory.into();

        let cookie = CoRegisterClassObject(
            &PASSKEY_CLSID,
            &factory_unknown,
            CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED,
        )
        .expect("CoRegisterClassObject failed");

        CoResumeClassObjects().expect("CoResumeClassObjects failed");

        tracing::info!(clsid = ?PASSKEY_CLSID, "COM server registered, waiting for requests");

        // Run the COM message pump on the main thread
        message_loop();

        tracing::info!("shutting down");
        CoRevokeClassObject(cookie).expect("CoRevokeClassObject failed");
        CoUninitialize();
    }
}

/// Simple Win32 message loop to keep the COM server alive.
///
/// # Safety
///
/// Must be called after COM has been initialized with `CoInitializeEx`.
/// The caller must ensure this runs on a thread that owns a message queue.
unsafe fn message_loop() {
    use windows::Win32::UI::WindowsAndMessaging::{GetMessageW, MSG};

    let mut msg = MSG::default();
    // GetMessageW returns 0 on WM_QUIT, -1 on error
    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
        // No translation/dispatch needed; COM handles its own messages
        // via the RPC infrastructure.
    }
}
