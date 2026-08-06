#![allow(clippy::unreadable_literal)]
use anyhow::bail;

use crate::ksu_uapi;
use std::fs;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

// Global driver fd cache. Atomic so a stale (closed) fd can be reset and
// re-acquired on EBADF. The old OnceLock permanently cached a dead fd (or
// -1), which broke every later ioctl for the rest of the process lifetime
// and disabled the whole post-fs-data flow when the early umh-spawned ksud
// hit a transient fd problem.
static DRIVER_FD: AtomicI32 = AtomicI32::new(-1);

fn scan_driver_fd() -> Option<RawFd> {
    let fd_dir = fs::read_dir("/proc/self/fd").ok()?;

    for entry in fd_dir.flatten() {
        if let Ok(fd_num) = entry.file_name().to_string_lossy().parse::<i32>() {
            let link_path = format!("/proc/self/fd/{fd_num}");
            if let Ok(target) = fs::read_link(&link_path) {
                let target_str = target.to_string_lossy();
                if target_str.contains("[ksu_driver]") {
                    return Some(fd_num);
                }
            }
        }
    }

    None
}

// Get cached driver fd.
// Tries prctl (seccomp-safe) first, falls back to sys_reboot for root processes.
fn init_driver_fd() -> Option<RawFd> {
    let fd = scan_driver_fd();
    if fd.is_none() {
        let mut fd = -1;
        unsafe {
            // prctl path: seccomp-safe (not blocked for untrusted_app).
            // Intercepted by ksu_handle_prctl in kernel supercall.c.
            libc::syscall(
                libc::SYS_prctl,
                ksu_uapi::KSU_INSTALL_MAGIC1,
                ksu_uapi::KSU_INSTALL_MAGIC2,
                &mut fd,
                0,
                0,
            );
        }
        if fd < 0 {
            // fallback: sys_reboot for root / non-seccomp processes
            unsafe {
                libc::syscall(
                    libc::SYS_reboot,
                    ksu_uapi::KSU_INSTALL_MAGIC1,
                    ksu_uapi::KSU_INSTALL_MAGIC2,
                    0,
                    &mut fd,
                );
            };
        }
        if fd >= 0 { Some(fd) } else { None }
    } else {
        fd
    }
}

fn get_driver_fd() -> RawFd {
    let cached = DRIVER_FD.load(Ordering::Relaxed);
    if cached >= 0 {
        return cached;
    }
    if let Some(fd) = init_driver_fd() {
        DRIVER_FD.store(fd, Ordering::Relaxed);
        fd
    } else {
        -1
    }
}

// ioctl wrapper using libc
pub(crate) fn ksuctl<T>(request: u32, arg: *mut T) -> std::io::Result<i32> {
    use std::io;

    let mut fd = get_driver_fd();
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    unsafe {
        let ret = libc::ioctl(fd as libc::c_int, request as i32, arg);
        if ret < 0 {
            let err = io::Error::last_os_error();
            // The cached fd may have been closed underneath us; drop it and
            // re-acquire once before giving up.
            if err.raw_os_error() == Some(libc::EBADF) {
                libc::close(fd);
                DRIVER_FD.store(-1, Ordering::Relaxed);
                fd = get_driver_fd();
                if fd >= 0 {
                    let ret2 = libc::ioctl(fd as libc::c_int, request as i32, arg);
                    if ret2 >= 0 {
                        return Ok(ret2);
                    }
                }
            }
            Err(err)
        } else {
            Ok(ret)
        }
    }
}

// API implementations
pub fn get_info() -> ksu_uapi::ksu_get_info_cmd {
    // Always query the kernel instead of caching: a cached all-zero struct
    // (from a transient ioctl failure) would make ensure_uapi_version_matched()
    // bail forever, disabling the whole post-fs-data flow.
    let mut cmd = ksu_uapi::ksu_get_info_cmd {
        version: 0,
        flags: 0,
        features: 0,
        uapi_version: 0,
    };
    if ksuctl(ksu_uapi::KSU_IOCTL_GET_INFO, &raw mut cmd).is_err() {
        let _ = ksuctl(ksu_uapi::KSU_IOCTL_GET_INFO_LEGACY, &raw mut cmd);
    }
    cmd
}

pub fn get_version() -> i32 {
    get_info().version as i32
}

pub fn is_late_load() -> bool {
    get_info().flags & ksu_uapi::KSU_GET_INFO_FLAG_LATE_LOAD != 0
}

pub fn is_lkm() -> bool {
    get_info().flags & ksu_uapi::KSU_GET_INFO_FLAG_LKM != 0
}

pub const fn uapi_version() -> u32 {
    ksu_uapi::KERNEL_SU_UAPI_VERSION
}

pub fn runtime_mode() -> &'static str {
    if is_late_load() {
        "late-load"
    } else if is_lkm() {
        "lkm"
    } else {
        "built-in"
    }
}

pub fn ensure_uapi_version_matched() -> anyhow::Result<()> {
    let kernel_uapi = get_info().uapi_version;
    let userspace_uapi = uapi_version();
    if kernel_uapi != userspace_uapi {
        bail!(
            "UAPI version mismatch: kernel={kernel_uapi}, ksud={userspace_uapi}. Please update KernelSU!"
        );
    }
    Ok(())
}

pub fn grant_root() -> std::io::Result<()> {
    ksuctl(ksu_uapi::KSU_IOCTL_GRANT_ROOT, std::ptr::null_mut::<u8>())?;
    Ok(())
}

fn report_event(event: u32) {
    let mut cmd = ksu_uapi::ksu_report_event_cmd { event };
    let _ = ksuctl(ksu_uapi::KSU_IOCTL_REPORT_EVENT, &raw mut cmd);
}

pub fn report_post_fs_data() {
    report_event(ksu_uapi::EVENT_POST_FS_DATA);
}

pub fn report_boot_complete() {
    report_event(ksu_uapi::EVENT_BOOT_COMPLETED);
}

pub fn report_module_mounted() {
    report_event(ksu_uapi::EVENT_MODULE_MOUNTED);
}

pub fn check_kernel_safemode() -> bool {
    let mut cmd = ksu_uapi::ksu_check_safemode_cmd { in_safe_mode: 0 };
    let _ = ksuctl(ksu_uapi::KSU_IOCTL_CHECK_SAFEMODE, &raw mut cmd);
    cmd.in_safe_mode != 0
}

pub fn set_sepolicy(payload: *const u8, payload_len: u64) -> std::io::Result<i32> {
    let mut ioctl_cmd = crate::ksu_uapi::ksu_set_sepolicy_cmd {
        data_len: payload_len,
        data: payload as u64,
    };

    ksuctl(ksu_uapi::KSU_IOCTL_SET_SEPOLICY, &raw mut ioctl_cmd)
}

/// Get feature value and support status from kernel
/// Returns (value, supported)
pub fn get_feature(feature_id: u32) -> std::io::Result<(u64, bool)> {
    let mut cmd = ksu_uapi::ksu_get_feature_cmd {
        feature_id,
        value: 0,
        supported: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_GET_FEATURE, &raw mut cmd)?;
    Ok((cmd.value, cmd.supported != 0))
}

/// Set feature value in kernel
pub fn set_feature(feature_id: u32, value: u64) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_set_feature_cmd { feature_id, value };
    ksuctl(ksu_uapi::KSU_IOCTL_SET_FEATURE, &raw mut cmd)?;
    Ok(())
}

pub fn get_wrapped_fd(fd: RawFd) -> std::io::Result<RawFd> {
    let mut cmd = ksu_uapi::ksu_get_wrapper_fd_cmd {
        fd: fd as u32,
        flags: 0,
    };
    let result = ksuctl(ksu_uapi::KSU_IOCTL_GET_WRAPPER_FD, &raw mut cmd)?;
    Ok(result)
}

pub fn get_sulog_fd() -> std::io::Result<RawFd> {
    let mut cmd = ksu_uapi::ksu_get_sulog_fd_cmd { flags: 0 };
    let result = ksuctl(ksu_uapi::KSU_IOCTL_GET_SULOG_FD, &raw mut cmd)?;
    Ok(result)
}

/// Get mark status for a process (pid=0 returns total marked count)
pub fn mark_get(pid: i32) -> std::io::Result<u32> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_GET,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(cmd.result)
}

/// Mark a process (pid=0 marks all processes)
pub fn mark_set(pid: i32) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_MARK,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Unmark a process (pid=0 unmarks all processes)
pub fn mark_unset(pid: i32) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_UNMARK,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Refresh mark for all running processes
pub fn mark_refresh() -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_REFRESH,
        pid: 0,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

pub fn nuke_ext4_sysfs(mnt: &str) -> anyhow::Result<()> {
    let c_mnt = std::ffi::CString::new(mnt)?;
    let mut ioctl_cmd = ksu_uapi::ksu_nuke_ext4_sysfs_cmd {
        arg: c_mnt.as_ptr() as u64,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_NUKE_EXT4_SYSFS, &raw mut ioctl_cmd)?;
    Ok(())
}

/// Wipe all entries from umount list
pub fn umount_list_wipe() -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: 0,
        flags: 0,
        mode: ksu_uapi::KSU_UMOUNT_WIPE,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Add mount point to umount list
pub fn umount_list_add(path: &str, flags: u32) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: c_path.as_ptr() as u64,
        flags,
        mode: ksu_uapi::KSU_UMOUNT_ADD,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Delete mount point from umount list
pub fn umount_list_del(path: &str) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: c_path.as_ptr() as u64,
        flags: 0,
        mode: ksu_uapi::KSU_UMOUNT_DEL,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Set current process's process group to init_group (pgid = 0)
pub fn set_init_pgrp() -> std::io::Result<()> {
    ksuctl(
        ksu_uapi::KSU_IOCTL_SET_INIT_PGRP,
        std::ptr::null_mut::<u8>(),
    )?;
    Ok(())
}

pub fn set_ksu_no_new_privs() -> anyhow::Result<()> {
    let result = ksuctl(
        ksu_uapi::KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT,
        std::ptr::null_mut::<u8>(),
    )?;
    if result != 0 {
        bail!("unexpected result: {result}");
    }
    Ok(())
}

#[repr(C)]
struct KsuSusfsIoctlCmd {
    cmd_id: u32,
    arg_ptr: u64,
}

pub fn susfs_ioctl<T>(cmd_id: u64, arg: &mut T) -> anyhow::Result<i32> {
    let mut ioctl_cmd = KsuSusfsIoctlCmd {
        cmd_id: cmd_id as u32,
        arg_ptr: arg as *mut T as u64,
    };
    ksuctl(0x55u32, &raw mut ioctl_cmd)
        .map_err(|e| anyhow::anyhow!("susfs ioctl: {e}"))
}
