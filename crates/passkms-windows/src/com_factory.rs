//! COM class factory for the plugin authenticator.
//!
//! Windows calls `IClassFactory::CreateInstance` to instantiate our
//! `IPluginAuthenticator` implementation when a WebAuthn operation
//! targets our registered CLSID.

use std::sync::Arc;

use windows::core::{implement, IUnknown, Interface, Ref, GUID};
use windows::Win32::Foundation::CLASS_E_NOAGGREGATION;
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};

use crate::bindings::IPluginAuthenticator;
use crate::com_plugin::PluginAuthenticator;

/// Our COM CLSID. Must match the MSIX manifest and registration call.
///
/// Generated once: `a3b2c1d0-e4f5-6789-abcd-ef0123456789`
pub const PASSKEY_CLSID: GUID = GUID::from_u128(0xa3b2c1d0_e4f5_6789_abcd_ef0123456789);

/// COM class factory that creates `PluginAuthenticator` instances.
#[implement(IClassFactory)]
pub struct PasskeyClassFactory {
    runtime: Arc<tokio::runtime::Runtime>,
    authenticator: Arc<passkms_core::Authenticator>,
}

impl PasskeyClassFactory {
    pub fn new(
        runtime: Arc<tokio::runtime::Runtime>,
        authenticator: Arc<passkms_core::Authenticator>,
    ) -> Self {
        Self {
            runtime,
            authenticator,
        }
    }
}

impl IClassFactory_Impl for PasskeyClassFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut std::ffi::c_void,
    ) -> windows::core::Result<()> {
        // SAFETY: riid is provided by the COM runtime and guaranteed non-null per the
        // IClassFactory::CreateInstance contract.
        let riid_val = unsafe { &*riid };
        tracing::debug!(
            riid = ?riid_val,
            has_outer = punkouter.is_some(),
            "CreateInstance called"
        );

        // SAFETY: ppvobject is provided by the COM runtime; initializing to null is the
        // standard pattern before attempting QueryInterface.
        unsafe {
            *ppvobject = std::ptr::null_mut();
        }

        // Aggregation not supported
        if punkouter.is_some() {
            tracing::debug!("rejecting aggregation request");
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        // Only create instances for IPluginAuthenticator or IUnknown
        if *riid_val != IPluginAuthenticator::IID && *riid_val != IUnknown::IID {
            tracing::debug!(
                riid = ?riid_val,
                expected_plugin = ?IPluginAuthenticator::IID,
                expected_unknown = ?IUnknown::IID,
                "rejecting unsupported interface request"
            );
            return Err(windows::core::Error::from(
                windows::Win32::Foundation::E_NOINTERFACE,
            ));
        }

        tracing::debug!("creating new PluginAuthenticator instance");
        let authenticator =
            PluginAuthenticator::new(self.runtime.clone(), self.authenticator.clone());
        let unknown: IUnknown = authenticator.into();

        // SAFETY: unknown is a valid IUnknown we just created; riid_val and ppvobject are
        // valid pointers from the COM runtime. QueryInterface follows COM reference counting.
        let result = unsafe { unknown.query(riid_val, ppvobject).ok() };
        tracing::debug!(success = result.is_ok(), "CreateInstance completed");
        result
    }

    fn LockServer(&self, flock: windows_core::BOOL) -> windows::core::Result<()> {
        tracing::debug!(lock = flock.as_bool(), "LockServer called");
        // We don't track lock count for now; the process stays alive
        // as long as the COM message pump is running.
        Ok(())
    }
}
