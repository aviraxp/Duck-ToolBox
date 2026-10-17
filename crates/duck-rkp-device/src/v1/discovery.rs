use duck_core::Sysroot;
use std::{fs, path::PathBuf};

pub(crate) const APP_PROCESS: &str = "/system/bin/app_process";

/// Use only system-owned APKs. The proxy must match this device's parcelable layout.
pub(crate) fn find_aidl_apk(sysroot: &Sysroot) -> Option<PathBuf> {
    for directory in ["priv-app", "app"] {
        let root = sysroot.path(format!("/apex/com.android.rkpd/{directory}"));
        let mut entries: Vec<_> = fs::read_dir(root)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        entries.sort();
        for entry in entries {
            let apk = entry.join("rkpdapp.apk");
            if apk.is_file() {
                return Some(apk);
            }
        }
    }
    for root in ["/system/priv-app", "/system/app", "/system_ext/priv-app"] {
        let apk = sysroot.path(format!("{root}/RemoteProvisioner/RemoteProvisioner.apk"));
        if apk.is_file() {
            return Some(apk);
        }
    }
    None
}
