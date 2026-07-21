use std::ffi::CStr;
use anyhow::{Result, anyhow};
use libc::{syscall, SYS_reboot, c_char};

const KSU_INSTALL_MAGIC1: u64 = 0xDEADBEEF;
const SUSFS_MAGIC: u64 = 0xFAFAFAFA;

const CMD_SUSFS_SHOW_VERSION: u64 = 0x555e1;
const CMD_SUSFS_SHOW_ENABLED_FEATURES: u64 = 0x555e2;
const CMD_SUSFS_SHOW_VARIANT: u64 = 0x555e3;
const CMD_SUSFS_ADD_SUS_PATH: u64 = 0x55550;
const CMD_SUSFS_ADD_SUS_PATH_LOOP: u64 = 0x55553;
const CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY: u64 = 0x55572;
const CMD_SUSFS_ADD_SUS_MAP: u64 = 0x60020;
const CMD_SUSFS_SET_UNAME: u64 = 0x55590;
const CMD_SUSFS_ENABLE_LOG: u64 = 0x555a0;
const CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING: u64 = 0x60010;
const CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS: u64 = 0x55561;
const CMD_SUSFS_ADD_OPEN_REDIRECT: u64 = 0x555c0;

const SUSFS_ENABLED_FEATURES_SIZE: usize = 8192;
const SUSFS_MAX_VERSION_BUFSIZE: usize = 16;
const SUSFS_MAX_VARIANT_BUFSIZE: usize = 16;

const ERR_CMD_NOT_SUPPORTED: i32 = 126;

#[repr(C)]
struct SusfsVersion {
    version: [u8; SUSFS_MAX_VERSION_BUFSIZE],
    err: i32,
}

#[repr(C)]
struct SusfsVariant {
    variant: [u8; SUSFS_MAX_VARIANT_BUFSIZE],
    err: i32,
}

#[repr(C)]
struct SusfsEnabledFeatures {
    features: [u8; SUSFS_ENABLED_FEATURES_SIZE],
    err: i32,
}

#[repr(C)]
struct SusfsUname {
    release: [u8; 65],
    version: [u8; 65],
    err: i32,
}

#[repr(C)]
struct SusfsLog {
    enabled: u32,
    err: i32,
}

#[repr(C)]
struct SusfsAvcLogSpoofing {
    enabled: u32,
    err: i32,
}

#[repr(C)]
struct SusfsHideSusMnts {
    enabled: u32,
    err: i32,
}

#[repr(C)]
struct SusfsOpenRedirect {
    target_pathname: [u8; 256],
    redirected_pathname: [u8; 256],
    uid_scheme: u32,
    err: i32,
}

#[repr(C)]
struct SusfsKstat {
    is_statically: u32,
    target_ino: u64,
    target_pathname: [u8; 256],
    spoofed_ino: u64,
    spoofed_dev: u64,
    spoofed_nlink: u32,
    spoofed_size: u64,
    spoofed_atime_tv_sec: i64,
    spoofed_atime_tv_nsec: u64,
    spoofed_mtime_tv_sec: i64,
    spoofed_mtime_tv_nsec: u64,
    spoofed_ctime_tv_sec: i64,
    spoofed_ctime_tv_nsec: u64,
    spoofed_blocks: u64,
    spoofed_blksize: i64,
    flags: u32,
    err: i32,
}

#[repr(C)]
struct SusfsMap {
    target_pathname: [u8; 256],
    err: i32,
}

#[repr(C)]
struct SusfsPath {
    target_ino: u64,
    target_pathname: [u8; 256],
    err: i32,
}

pub fn show_version() -> Result<()> {
    let mut cmd = SusfsVersion {
        version: [0; SUSFS_MAX_VERSION_BUFSIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_VERSION, &mut cmd as *mut _);
    }
    check_unsupported(cmd.err, CMD_SUSFS_SHOW_VERSION)?;
    if cmd.err == 0 {
        let version = unsafe { CStr::from_ptr(cmd.version.as_ptr() as *const c_char) }.to_string_lossy();
        println!("{}", version);
        Ok(())
    } else {
        Err(anyhow!("Invalid (Error: {})", cmd.err))
    }
}

pub fn show_variant() -> Result<()> {
    let mut cmd = SusfsVariant {
        variant: [0; SUSFS_MAX_VARIANT_BUFSIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_VARIANT, &mut cmd as *mut _);
    }
    check_unsupported(cmd.err, CMD_SUSFS_SHOW_VARIANT)?;
    if cmd.err == 0 {
        let variant = unsafe { CStr::from_ptr(cmd.variant.as_ptr() as *const c_char) }.to_string_lossy();
        println!("{}", variant);
        Ok(())
    } else {
        Err(anyhow!("Invalid (Error: {})", cmd.err))
    }
}

pub fn show_features(check_only: bool) -> Result<()> {
    let mut cmd = SusfsEnabledFeatures {
        features: [0; SUSFS_ENABLED_FEATURES_SIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_ENABLED_FEATURES, &mut cmd as *mut _);
    }
    check_unsupported(cmd.err, CMD_SUSFS_SHOW_ENABLED_FEATURES)?;
    let features_cstr = unsafe { CStr::from_ptr(cmd.features.as_ptr() as *const c_char) };
    let has_features = cmd.err == 0 && !features_cstr.to_bytes().is_empty();
    if check_only {
        if has_features {
            println!("Supported");
            Ok(())
        } else {
            Err(anyhow!("Unsupported"))
        }
    } else if has_features {
        print!("{}", features_cstr.to_string_lossy());
        Ok(())
    } else {
        Err(anyhow!("Invalid (Error: {})", cmd.err))
    }
}

pub fn set_uname(release: &str, version: &str) -> Result<()> {
    let mut cmd = SusfsUname {
        release: [0; 65],
        version: [0; 65],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    let release_bytes = release.as_bytes();
    let version_bytes = version.as_bytes();
    if release_bytes.len() >= cmd.release.len() || version_bytes.len() >= cmd.version.len() {
        anyhow::bail!("String too long");
    }
    cmd.release[..release_bytes.len()].copy_from_slice(release_bytes);
    cmd.version[..version_bytes.len()].copy_from_slice(version_bytes);
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SET_UNAME, &mut cmd);
    }
    if cmd.err != 0 {
        anyhow::bail!("Failed to set uname: err={}", cmd.err);
    }
    Ok(())
}

pub fn enable_log(enabled: bool) -> Result<()> {
    let mut cmd = SusfsLog {
        enabled: u32::from(enabled),
        err: ERR_CMD_NOT_SUPPORTED,
    };
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ENABLE_LOG, &mut cmd);
    }
    if cmd.err != 0 {
        anyhow::bail!("Failed to enable_log: err={}", cmd.err);
    }
    Ok(())
}

pub fn enable_avc_log_spoofing(enabled: bool) -> Result<()> {
    let mut cmd = SusfsAvcLogSpoofing {
        enabled: u32::from(enabled),
        err: ERR_CMD_NOT_SUPPORTED,
    };
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING, &mut cmd);
    }
    if cmd.err != 0 {
        anyhow::bail!("Failed to enable_avc_log_spoofing: err={}", cmd.err);
    }
    Ok(())
}

pub fn hide_sus_mnts_for_non_su_procs(enabled: bool) -> Result<()> {
    let mut cmd = SusfsHideSusMnts {
        enabled: u32::from(enabled),
        err: ERR_CMD_NOT_SUPPORTED,
    };
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS, &mut cmd);
    }
    if cmd.err != 0 {
        anyhow::bail!("Failed to hide_sus_mnts: err={}", cmd.err);
    }
    Ok(())
}

pub fn add_open_redirect(target: &str, redirected: &str, uid_scheme: u32) -> Result<()> {
    let mut cmd = SusfsOpenRedirect {
        target_pathname: [0; 256],
        redirected_pathname: [0; 256],
        uid_scheme,
        err: ERR_CMD_NOT_SUPPORTED,
    };
    let target_bytes = target.as_bytes();
    let redirected_bytes = redirected.as_bytes();
    if target_bytes.len() >= cmd.target_pathname.len() || redirected_bytes.len() >= cmd.redirected_pathname.len() {
        anyhow::bail!("Path too long");
    }
    cmd.target_pathname[..target_bytes.len()].copy_from_slice(target_bytes);
    cmd.redirected_pathname[..redirected_bytes.len()].copy_from_slice(redirected_bytes);
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_OPEN_REDIRECT, &mut cmd);
    }
    if cmd.err != 0 {
        anyhow::bail!("Failed to add open redirect: err={}", cmd.err);
    }
    Ok(())
}

pub fn add_sus_map(path: &str) -> Result<()> {
    let mut cmd = SusfsMap {
        target_pathname: [0; 256],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    let path_bytes = path.as_bytes();
    if path_bytes.len() >= cmd.target_pathname.len() {
        anyhow::bail!("Path too long");
    }
    cmd.target_pathname[..path_bytes.len()].copy_from_slice(path_bytes);
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_SUS_MAP, &mut cmd);
    }
    if cmd.err != 0 {
        anyhow::bail!("Failed to add sus map: err={}", cmd.err);
    }
    Ok(())
}

pub fn add_sus_path(path: &str) -> Result<()> {
    let mut cmd = SusfsPath {
        target_ino: 0,
        target_pathname: [0; 256],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    let path_bytes = path.as_bytes();
    if path_bytes.len() >= cmd.target_pathname.len() {
        anyhow::bail!("Path too long");
    }
    cmd.target_pathname[..path_bytes.len()].copy_from_slice(path_bytes);
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_SUS_PATH, &mut cmd);
    }
    if cmd.err != 0 {
        anyhow::bail!("Failed to add sus path: err={}", cmd.err);
    }
    Ok(())
}

pub fn add_sus_path_loop(path: &str) -> Result<()> {
    let mut cmd = SusfsPath {
        target_ino: 0,
        target_pathname: [0; 256],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    let path_bytes = path.as_bytes();
    if path_bytes.len() >= cmd.target_pathname.len() {
        anyhow::bail!("Path too long");
    }
    cmd.target_pathname[..path_bytes.len()].copy_from_slice(path_bytes);
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_SUS_PATH_LOOP, &mut cmd);
    }
    if cmd.err != 0 {
        anyhow::bail!("Failed to add sus path loop: err={}", cmd.err);
    }
    Ok(())
}

pub fn add_sus_kstat(path: &str) -> Result<()> {
    let _ = path;
    Ok(())
}

pub fn update_sus_kstat(path: &str) -> Result<()> {
    let _ = path;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn add_sus_kstat_statically(
    path: &str,
    ino: u64,
    dev: u64,
    nlink: u32,
    size: u64,
    atime_sec: i64,
    atime_nsec_opt: u64,
    mtime_sec: i64,
    mtime_nsec_opt: u64,
    ctime_sec: i64,
    ctime_nsec_opt: u64,
    blocks: u64,
    blksize: i64,
) -> Result<()> {
    let mut cmd = SusfsKstat {
        is_statically: 1,
        target_ino: 0,
        target_pathname: [0; 256],
        spoofed_ino: ino,
        spoofed_dev: dev,
        spoofed_nlink: nlink,
        spoofed_size: size,
        spoofed_atime_tv_sec: atime_sec,
        spoofed_atime_tv_nsec: atime_nsec_opt,
        spoofed_mtime_tv_sec: mtime_sec,
        spoofed_mtime_tv_nsec: mtime_nsec_opt,
        spoofed_ctime_tv_sec: ctime_sec,
        spoofed_ctime_tv_nsec: ctime_nsec_opt,
        spoofed_blocks: blocks,
        spoofed_blksize: blksize,
        flags: 0,
        err: ERR_CMD_NOT_SUPPORTED,
    };
    let path_bytes = path.as_bytes();
    if path_bytes.len() >= cmd.target_pathname.len() {
        anyhow::bail!("Path too long");
    }
    cmd.target_pathname[..path_bytes.len()].copy_from_slice(path_bytes);
    unsafe {
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, &mut cmd);
    }
    if cmd.err != 0 {
        anyhow::bail!("Failed to add sus kstat statically: err={}", cmd.err);
    }
    Ok(())
}

fn check_unsupported(err: i32, cmd: u64) -> Result<()> {
    if err == ERR_CMD_NOT_SUPPORTED {
        return Err(anyhow!("CMD: '0x{:x}', SUSFS operation not supported, please enable it in kernel", cmd));
    }
    Ok(())
}
