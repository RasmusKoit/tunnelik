//! Process Windows starts for the package's hidden "Plugin" app whenever a VPN event needs the
//! plugin. It only hands Windows the plugin's background task class; the work happens there.

#![windows_subsystem = "windows"]

#[cfg(windows)]
fn main() -> windows_core::Result<()> {
    use windows::ApplicationModel::Core::CoreApplication;
    use windows::Foundation::{IGetActivationFactory, IGetActivationFactory_Impl};
    use windows_core::{Error, HRESULT, HSTRING, IInspectable, Interface, Result, implement};

    const CLASS_E_CLASSNOTAVAILABLE: HRESULT = HRESULT(0x8004_0111_u32 as i32);

    #[implement(IGetActivationFactory)]
    struct Factories;

    impl IGetActivationFactory_Impl for Factories_Impl {
        fn GetActivationFactory(&self, class: &HSTRING) -> Result<IInspectable> {
            match wgw11_plugin::activation_factory(class) {
                Some(factory) => factory.cast(),
                None => Err(Error::new(
                    CLASS_E_CLASSNOTAVAILABLE,
                    format!("unknown class {class}"),
                )),
            }
        }
    }

    let factories: IGetActivationFactory = Factories.into();
    CoreApplication::RunWithActivationFactories(&factories)
}

#[cfg(not(windows))]
fn main() {}
