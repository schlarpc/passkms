// COM code is inherently unsafe
#![allow(unsafe_code)]

//! passkms-windows: Out-of-process COM server for the Windows WebAuthn Plugin API.
//!
//! This binary registers as a COM server and responds to IPluginAuthenticator
//! calls from the Windows WebAuthn platform. It bridges to `passkms-core` for
//! all FIDO2 authenticator logic and KMS interaction.

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

use com_factory::{PasskeyClassFactory, PASSKEY_CLSID};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("passkms-windows starting");

    // Build a tokio runtime for async KMS operations
    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime"),
    );

    unsafe {
        // Initialize COM for multi-threaded apartment
        CoInitializeEx(None, COINIT_MULTITHREADED)
            .ok()
            .expect("CoInitializeEx failed");

        // Create and register our class factory
        let factory = PasskeyClassFactory::new(runtime);
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
unsafe fn message_loop() {
    use windows::Win32::UI::WindowsAndMessaging::{GetMessageW, MSG};

    let mut msg = MSG::default();
    // GetMessageW returns 0 on WM_QUIT, -1 on error
    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
        // No translation/dispatch needed; COM handles its own messages
        // via the RPC infrastructure.
    }
}
