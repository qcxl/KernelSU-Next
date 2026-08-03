//! SUSFS 配置持久化 — 保存/恢复 SUSFS 规则到 JSON
//!
//! 每次用户执行写命令（add-sus-path, set-uname 等）时自动保存。
//! 重启后首次执行任何 ksud 命令时自动恢复。

use std::path::Path;
use std::collections::HashMap;
use anyhow::{Result, Context};
use const_format::concatcp;
use serde::{Serialize, Deserialize};

use crate::susfsd;
use crate::defs;

/// SUSFS 持久化配置
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct SusfsConfig {
    pub uname_release: String,
    pub uname_version: String,
    pub sus_paths: Vec<String>,
    pub sus_path_loops: Vec<String>,
    pub sus_maps: Vec<String>,
    pub sus_mounts: Vec<String>,
    pub enable_log: bool,
    pub enable_avc_log_spoofing: bool,
    pub hide_sus_mnts: bool,
    #[serde(default)]
    pub set_props: HashMap<String, String>,
    #[serde(default)]
    pub delete_props: Vec<String>,
}

const CONFIG_PATH: &str = concatcp!(crate::defs::ADB_DIR, "ksu/susfs_config.json");

/// 每 boot 只应用一次的标记文件。/dev 是 tmpfs，重启后自动清空，
/// 因此该标记天然实现"每 boot 一次"语义（替代旧的进程内 AtomicBool，
/// 后者在每次 ksud 命令都是独立进程时每次都会触发全量 apply，导致每条
/// 命令都要做 ~19 次 resetprop 子进程 + 10 次 SUSFS ioctl，耗时 200-500ms）。
const APPLY_MARKER: &str = "/dev/susfs_ksu_applied";

/// 内置默认配置（格式 /data 后也自动生效）
fn default_config() -> SusfsConfig {
    SusfsConfig {
        uname_release: "4.19.304".to_string(),
        uname_version: "#1 SMP PREEMPT Fri Feb 9 00:58:10 UTC 2024".to_string(),
        sus_paths: vec![
            "/system/bin/su".to_string(),
            "/odm/bin/su".to_string(),
            "/data/adb/ksu/su".to_string(),
            "/system/addon.d".to_string(),
            "/system/build.prop".to_string(),
        ],
        sus_path_loops: vec![],
        sus_maps: vec!["/data/adb/".to_string()],
        sus_mounts: vec!["/vendor".to_string(), "/odm".to_string()],
        enable_log: false,
        enable_avc_log_spoofing: true,
        hide_sus_mnts: true,
        set_props: HashMap::from([
            ("ro.build.type".into(), "user".into()),
            ("ro.build.flavor".into(), "OnePlus8T-user".into()),
            ("ro.build.display.id".into(), "RKQ1.211119.001".into()),
            ("ro.debuggable".into(), "0".into()),
            ("ro.build.user".into(), "jenkins".into()),
            ("ro.build.host".into(), "rd-build-193".into()),
            // Partition prop variants must match ro.build.* or scanners
            // (Hunter) flag the contradiction as "ROM may be modified".
            ("ro.product.build.type".into(), "user".into()),
            ("ro.system.build.type".into(), "user".into()),
            ("ro.system_ext.build.type".into(), "user".into()),
            ("ro.vendor.build.type".into(), "user".into()),
            ("ro.vendor_dlkm.build.type".into(), "user".into()),
            ("ro.odm.build.type".into(), "user".into()),
            ("ro.product.build.tags".into(), "release-keys".into()),
            // Do NOT spoof ro.product.*.model partition variants: the CIB
            // mobile banking app (com.cib.cibmb) pops "unsafe device (110)"
            // and force-closes when they are changed from the real KB2005.
            // Keep them at vendor build.prop values; ro.product.model is
            // already KB2000 (real) and Hunter accepts the mix.
            ("ro.boot.verifiedbootstate".into(), "green".into()),
            // Clear ro.lineage.* / ro.modversion to empty STRING (NOT delete)
            // via resetprop. These props are a LineageOS fingerprint that
            // the CIB bank app (com.cib.cibmb) detects -> "unsafe device
            // (110)" force-close. resetprop setting "" uses the bionic
            // protocol which keeps the prop area structure intact (no
            // Hunter hole), unlike the kernel property_set kernel_write
            // path which leaves orphan entries.
            ("ro.lineage.version".into(), "".into()),
            ("ro.lineage.build.version".into(), "".into()),
            ("ro.lineage.build.version.plat.rev".into(), "".into()),
            ("ro.lineage.build.version.plat.sdk".into(), "".into()),
            ("ro.lineage.device".into(), "".into()),
            ("ro.lineage.display.version".into(), "".into()),
            ("ro.lineage.releasetype".into(), "".into()),
            ("ro.lineagelegal.url".into(), "".into()),
            ("ro.modversion".into(), "".into()),
        ]),
        /* Do NOT delete ro.lineage.* / ro.modversion via resetprop --delete:
         * deletion zeroes the name's first byte breaking the trie, leaving
         * a "hole" that Hunter detects. Clearing to empty string via
         * set_props (resetprop <key> "") keeps structure intact. See the
         * set_props entries above. */
        delete_props: vec![],
    }
}

/// 加载配置，文件不存在时返回内置默认值（而非空配置）
pub fn load() -> Result<SusfsConfig> {
    let path = Path::new(CONFIG_PATH);
    if !path.exists() {
        return Ok(default_config());
    }
    let data = std::fs::read_to_string(path).context("read susfs config")?;
    serde_json::from_str(&data).context("parse susfs config")
}

/// 保存配置
pub fn save(config: &SusfsConfig) -> Result<()> {
    let path = Path::new(CONFIG_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create config dir")?;
    }
    // 原子写入：先写 tmp 再 rename
    let tmp = format!("{}.tmp", CONFIG_PATH);
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(&tmp, &json).context("write tmp config")?;
    std::fs::rename(&tmp, path).context("rename config")?;
    Ok(())
}

/// 将配置中的所有规则恢复到内核（通过 ioctl）
pub fn apply(config: &SusfsConfig) {
    // uname
    if !config.uname_release.is_empty() || !config.uname_version.is_empty() {
        let r = if config.uname_release.is_empty() { "default" } else { &config.uname_release };
        let v = if config.uname_version.is_empty() { "default" } else { &config.uname_version };
        let _ = susfsd::set_uname(r, v);
    }

    // sus_paths
    for path in &config.sus_paths {
        let _ = susfsd::add_sus_path(path);
    }

    // sus_path_loops
    for path in &config.sus_path_loops {
        let _ = susfsd::add_sus_path_loop(path);
    }

    // sus_maps
    for path in &config.sus_maps {
        let _ = susfsd::add_sus_map(path);
    }

    // sus_mounts
    for path in &config.sus_mounts {
        let _ = susfsd::add_sus_mount(path);
    }

    // 开关
    if config.enable_log {
        let _ = susfsd::enable_log(true);
    }
    if config.enable_avc_log_spoofing {
        let _ = susfsd::enable_avc_log_spoofing(true);
    }
    if config.hide_sus_mnts {
        let _ = susfsd::hide_sus_mnts_for_non_su_procs(true);
    }

    // resetprop：先设置后删除，避免冲突
    for (key, value) in &config.set_props {
        let _ = susfsd::set_prop(key, value);
    }
    for key in &config.delete_props {
        let _ = susfsd::delete_prop(key);
    }
}

/// 在 CLI 入口处调用：每个 boot 只恢复一次（用 /dev 标记，重启即清空）。
/// 注意：这里不能简单地用 is_boot_restored() 跳过整个 apply，
/// 因为用户可能通过 `ksud susfs add-sus-path` 添加了自定义规则，
/// 这些规则保存在 JSON 中，重启后需要重新应用。
/// 内核 restore 只负责默认规则，用户自定义规则必须靠 JSON apply。
pub fn restore_if_needed() {
    // /dev 为 tmpfs，重启即清空，故该标记保证"每 boot 一次"
    if Path::new(APPLY_MARKER).exists() {
        return;
    }
    match load() {
        Ok(config) => {
            let has_rules = !config.sus_paths.is_empty()
                || !config.sus_maps.is_empty()
                || !config.uname_release.is_empty()
                || config.enable_log
                || config.enable_avc_log_spoofing
                || config.hide_sus_mnts
                || !config.set_props.is_empty()
                || !config.delete_props.is_empty();
            if has_rules {
                log::info!("restoring SUSFS config from {}", CONFIG_PATH);
                apply(&config);
                // 如果配置文件不存在（首次启动/格式 /data），保存内置默认值到磁盘
                if !Path::new(CONFIG_PATH).exists() {
                    let _ = save(&config);
                }
            }
        }
        Err(e) => {
            log::warn!("failed to load SUSFS config: {e:#}");
        }
    }
    // 无论成功与否都标记已尝试，避免每条命令反复重试；
    // 失败时用户可显式执行 `ksud susfs add-*` 手动重试。
    let _ = std::fs::write(APPLY_MARKER, b"1");
}

/// 从当前 susfsd 模块读取状态构建配置（用于后续保存）
pub fn from_susfs_state() -> SusfsConfig {
    SusfsConfig::default()
}

// ── 便捷更新函数：读 → 改 → 写 ────────────────────────────────────────────

pub fn append_sus_path(path: &str) -> Result<()> {
    let mut config = load().unwrap_or_default();
    if !config.sus_paths.iter().any(|p| p == path) {
        config.sus_paths.push(path.to_string());
        save(&config)
    } else {
        Ok(())
    }
}

pub fn append_sus_map(path: &str) -> Result<()> {
    let mut config = load().unwrap_or_default();
    if !config.sus_maps.iter().any(|p| p == path) {
        config.sus_maps.push(path.to_string());
        save(&config)
    } else {
        Ok(())
    }
}

pub fn append_sus_mount(path: &str) -> Result<()> {
    let mut config = load().unwrap_or_default();
    if !config.sus_mounts.iter().any(|p| p == path) {
        config.sus_mounts.push(path.to_string());
        save(&config)
    } else {
        Ok(())
    }
}

pub fn set_uname(release: &str, version: &str) -> Result<()> {
    let mut config = load().unwrap_or_default();
    config.uname_release = release.to_string();
    config.uname_version = version.to_string();
    save(&config)
}

pub fn set_toggle<F>(updater: F) -> Result<()>
where
    F: FnOnce(&mut SusfsConfig),
{
    let mut config = load().unwrap_or_default();
    updater(&mut config);
    save(&config)
}
