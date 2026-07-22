//! SUSFS 配置持久化 — 保存/恢复 SUSFS 规则到 JSON
//!
//! 每次用户执行写命令（add-sus-path, set-uname 等）时自动保存。
//! 重启后首次执行任何 ksud 命令时自动恢复。

use std::path::Path;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// 本进程启动后是否已恢复过（进程退出后自动清零）
static RESTORED: AtomicBool = AtomicBool::new(false);

/// 内置默认配置（格式 /data 后也自动生效）
fn default_config() -> SusfsConfig {
    SusfsConfig {
        uname_release: "4.19.304".to_string(),
        uname_version: "Default/4.19".to_string(),
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
        ]),
        delete_props: vec![
            "ro.lineage.version".into(),
            "ro.lineage.build.version".into(),
            "ro.lineage.build.version.plat.rev".into(),
            "ro.lineage.build.version.plat.sdk".into(),
            "ro.lineage.device".into(),
            "ro.lineage.display.version".into(),
            "ro.lineage.releasetype".into(),
            "ro.lineagelegal.url".into(),
            "ro.modversion".into(),
        ],
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

/// 在 CLI 入口处调用：每个进程生命周期内只恢复一次
pub fn restore_if_needed() {
    if RESTORED.load(Ordering::Relaxed) {
        return;
    }
    // 内核已在启动时通过 susfs_restore_boot() 应用了默认规则
    // （路径/挂载/映射/开关/属性均已设置）
    // JSON 配置仅用于用户通过 ksud CLI 添加的自定义规则，
    // 由内核标记跳过重复的 apply，避免冗余 ioctl 调用。
    if crate::susfsd::is_boot_restored() {
        log::info!("SUSFS already restored by kernel, skip JSON config apply");
        RESTORED.store(true, Ordering::Relaxed);
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
    RESTORED.store(true, Ordering::Relaxed);
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
