#[inline]
pub unsafe fn GetConsoleWindow() -> HWND {
    windows_core::link!("kernel32.dll" "system" fn GetConsoleWindow() -> HWND);
    unsafe { GetConsoleWindow() }
}
#[inline]
pub unsafe fn RoInitialize(inittype: RO_INIT_TYPE) -> windows_core::HRESULT {
    windows_core::link!("api-ms-win-core-winrt-l1-1-0.dll" "system" fn RoInitialize(inittype : RO_INIT_TYPE) -> windows_core::HRESULT);
    unsafe { RoInitialize(inittype) }
}
#[inline]
pub unsafe fn RoUninitialize() {
    windows_core::link!("api-ms-win-core-winrt-l1-1-0.dll" "system" fn RoUninitialize());
    unsafe { RoUninitialize() }
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HWND(pub *mut core::ffi::c_void);
windows_core::imp::define_interface!(
    IUserConsentVerifierInterop,
    IUserConsentVerifierInterop_Vtbl,
    0x39e050c3_4e74_441a_8dc0_b81104df949c
);
windows_core::imp::interface_hierarchy!(
    IUserConsentVerifierInterop,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl IUserConsentVerifierInterop {
    pub unsafe fn RequestVerificationForWindowAsync<T>(
        &self,
        appwindow: HWND,
        message: &windows_core::HSTRING,
    ) -> windows_core::Result<T>
    where
        T: windows_core::Interface,
    {
        let mut result__ = core::ptr::null_mut();
        unsafe {
            (windows_core::Interface::vtable(self).RequestVerificationForWindowAsync)(
                windows_core::Interface::as_raw(self),
                appwindow,
                core::mem::transmute_copy(message),
                &T::IID,
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IUserConsentVerifierInterop_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub RequestVerificationForWindowAsync: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        HWND,
        *mut core::ffi::c_void,
        *const windows_core::GUID,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
pub trait IUserConsentVerifierInterop_Impl: windows_core::IUnknownImpl {
    fn RequestVerificationForWindowAsync(
        &self,
        appwindow: HWND,
        message: &windows_core::HSTRING,
        riid: *const windows_core::GUID,
        asyncoperation: *mut *mut core::ffi::c_void,
    ) -> windows_core::Result<()>;
}
impl IUserConsentVerifierInterop_Vtbl {
    pub const fn new<Identity: IUserConsentVerifierInterop_Impl, const OFFSET: isize>() -> Self {
        unsafe extern "system" fn RequestVerificationForWindowAsync<
            Identity: IUserConsentVerifierInterop_Impl,
            const OFFSET: isize,
        >(
            this: *mut core::ffi::c_void,
            appwindow: HWND,
            message: *mut core::ffi::c_void,
            riid: *const windows_core::GUID,
            asyncoperation: *mut *mut core::ffi::c_void,
        ) -> windows_core::HRESULT {
            unsafe {
                let this: &Identity =
                    &*((this as *const *const ()).offset(OFFSET) as *const Identity);
                IUserConsentVerifierInterop_Impl::RequestVerificationForWindowAsync(
                    this,
                    core::mem::transmute_copy(&appwindow),
                    core::mem::transmute(&message),
                    core::mem::transmute_copy(&riid),
                    core::mem::transmute_copy(&asyncoperation),
                )
                .into()
            }
        }
        Self {
            base__: windows_core::IInspectable_Vtbl::new::<
                Identity,
                IUserConsentVerifierInterop,
                OFFSET,
            >(),
            RequestVerificationForWindowAsync: RequestVerificationForWindowAsync::<Identity, OFFSET>,
        }
    }
    pub fn matches(iid: &windows_core::GUID) -> bool {
        iid == &<IUserConsentVerifierInterop as windows_core::Interface>::IID
    }
}
impl windows_core::RuntimeName for IUserConsentVerifierInterop {}
windows_core::imp::define_interface!(
    IUserConsentVerifierStatics,
    IUserConsentVerifierStatics_Vtbl,
    0xaf4f3f91_564c_4ddc_b8b5_973447627c65
);
impl windows_core::RuntimeType for IUserConsentVerifierStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
    const NAME: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"Windows.Security.Credentials.UI.IUserConsentVerifierStatics",
    );
}
#[repr(C)]
pub struct IUserConsentVerifierStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CheckAvailabilityAsync: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub RequestVerificationAsync: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
pub const RO_INIT_MULTITHREADED: RO_INIT_TYPE = 1;
pub const RO_INIT_SINGLETHREADED: RO_INIT_TYPE = 0;
pub type RO_INIT_TYPE = i32;
pub const RPC_E_CHANGED_MODE: windows_core::HRESULT = windows_core::HRESULT(0x80010106_u32 as _);
pub const S_FALSE: windows_core::HRESULT = windows_core::HRESULT(0x1_u32 as _);
pub const S_OK: windows_core::HRESULT = windows_core::HRESULT(0x0_u32 as _);
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserConsentVerificationResult(pub i32);
impl UserConsentVerificationResult {
    pub const Verified: Self = Self(0);
    pub const DeviceNotPresent: Self = Self(1);
    pub const NotConfiguredForUser: Self = Self(2);
    pub const DisabledByPolicy: Self = Self(3);
    pub const DeviceBusy: Self = Self(4);
    pub const RetriesExhausted: Self = Self(5);
    pub const Canceled: Self = Self(6);
}
impl windows_core::imp::TypeKind for UserConsentVerificationResult {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for UserConsentVerificationResult {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Windows.Security.Credentials.UI.UserConsentVerificationResult;i4)",
    );
    const NAME: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"Windows.Security.Credentials.UI.UserConsentVerificationResult",
    );
}
pub struct UserConsentVerifier;
impl UserConsentVerifier {
    pub fn CheckAvailabilityAsync()
    -> windows_core::Result<windows_future::IAsyncOperation<UserConsentVerifierAvailability>> {
        Self::IUserConsentVerifierStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CheckAvailabilityAsync)(
                windows_core::Interface::as_raw(this),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    pub fn RequestVerificationAsync(
        message: &windows_core::HSTRING,
    ) -> windows_core::Result<windows_future::IAsyncOperation<UserConsentVerificationResult>> {
        Self::IUserConsentVerifierStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).RequestVerificationAsync)(
                windows_core::Interface::as_raw(this),
                core::mem::transmute_copy(message),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IUserConsentVerifierStatics<
        R,
        F: FnOnce(&IUserConsentVerifierStatics) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            UserConsentVerifier,
            IUserConsentVerifierStatics,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeName for UserConsentVerifier {
    const NAME: &'static str = "Windows.Security.Credentials.UI.UserConsentVerifier";
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserConsentVerifierAvailability(pub i32);
impl UserConsentVerifierAvailability {
    pub const Available: Self = Self(0);
    pub const DeviceNotPresent: Self = Self(1);
    pub const NotConfiguredForUser: Self = Self(2);
    pub const DisabledByPolicy: Self = Self(3);
    pub const DeviceBusy: Self = Self(4);
}
impl windows_core::imp::TypeKind for UserConsentVerifierAvailability {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for UserConsentVerifierAvailability {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Windows.Security.Credentials.UI.UserConsentVerifierAvailability;i4)",
    );
    const NAME: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"Windows.Security.Credentials.UI.UserConsentVerifierAvailability",
    );
}
