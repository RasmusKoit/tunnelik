//! Process Windows starts for the package's hidden "Plugin" app whenever a VPN event needs the
//! plugin. It only hands Windows the plugin's background task class; the work happens there.

#![windows_subsystem = "windows"]

#[cfg(windows)]
fn main() -> windows_core::Result<()> {
    use windows::ApplicationModel::Core::CoreApplication;
    use windows::Foundation::{IGetActivationFactory, IGetActivationFactory_Impl};
    use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize};
    use windows_core::{Error, HRESULT, HSTRING, IInspectable, Interface, Result, implement};

    const CLASS_E_CLASSNOTAVAILABLE: HRESULT = HRESULT(0x8004_0111_u32 as i32);

    #[implement(IGetActivationFactory)]
    struct Factories;

    impl IGetActivationFactory_Impl for Factories_Impl {
        fn GetActivationFactory(&self, class: &HSTRING) -> Result<IInspectable> {
            wgw11_plugin::file_log(&format!("host: factory requested for {class}"));
            match wgw11_plugin::activation_factory(class) {
                Some(factory) => factory.cast(),
                None => Err(Error::new(
                    CLASS_E_CLASSNOTAVAILABLE,
                    format!("unknown class {class}"),
                )),
            }
        }
    }

    std::panic::set_hook(Box::new(|info| {
        wgw11_plugin::file_log(&format!("host panicked: {info}"))
    }));
    let args: Vec<String> = std::env::args().skip(1).collect();
    wgw11_plugin::file_log(&format!("host: started with {args:?}"));

    // CoreApplication must first be used from the multithreaded apartment.
    // SAFETY: called once, on the main thread, before any other WinRT use.
    unsafe { RoInitialize(RO_INIT_MULTITHREADED)? };

    let factories: IGetActivationFactory = Factories.into();
    let result = CoreApplication::RunWithActivationFactories(&factories);
    wgw11_plugin::file_log(&format!("host: exiting with {result:?}"));
    result
}

#[cfg(not(windows))]
fn main() {}
