extern crate log;

use log::info;
use mem::windows::utils::get_process_id;
use std::{ffi::CString, path::Path};
use winapi::um::winnt::PROCESS_ALL_ACCESS;
use wow_rs;
use wow_rs::loadlibrary;

fn main() {
    env_logger::init();

    // let dll_path = String::from(
    //     "C:\\Users\\JYoun\\Code\\playground\\wow-rs\\target\\i686-pc-windows-msvc\\debug\\examples\\wow_rs_dll.dll",
    // );
    if Path::new("C:\\Users\\JYoun\\Code\\playground\\wow-rs\\target\\i686-pc-windows-msvc\\debug\\examples\\wow_rs_dll.dll").exists() == false {
        panic!("Unable to find DLL");
    }

    let dll_path = CString::new("C:\\Users\\JYoun\\Code\\playground\\wow-rs\\target\\i686-pc-windows-msvc\\debug\\examples\\wow_rs_dll.dll").unwrap();
    let process_name = "BloogsQuest.exe".to_string();
    let pid = get_process_id(&process_name).unwrap();

    let process_handle = wow_rs::open_process(PROCESS_ALL_ACCESS, false, pid);

    wow_rs::inject(process_handle, &dll_path).unwrap();

    // let wow_api = loadlibrary::Library::new("wow_rs_dll.dll").unwrap();

    info!("Stalling for 3 secs, then calling raise excep");

    std::thread::sleep(std::time::Duration::from_secs(3));

    // let raise_ex: FromWithin = wow_api.get_proc("FromWithin").unwrap();

    // raise_ex();
}

type FromWithin = extern "stdcall" fn();
