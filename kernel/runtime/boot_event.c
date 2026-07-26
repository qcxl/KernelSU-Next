#include "feature/selinux_hide.h"
#include "selinux/selinux.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/printk.h>

#include "policy/allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud_boot.h"
#include "runtime/ksud.h"
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"

extern void ksu_avc_spoof_late_init(void);

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
extern void susfs_restore_properties(void);
#endif

bool ksu_module_mounted __read_mostly = false;
bool ksu_boot_completed __read_mostly = false;

void on_post_fs_data(void)
{
	static bool done = false;

	if (done) {
		pr_debug("on_post_fs_data already done\n");
		return;
	}

	done = true;
	pr_debug("on_post_fs_data!\n");

	apply_kernelsu_rules();
	cache_sid();
	setup_ksu_cred();

	ksu_load_allow_list();
	ksu_observer_init();
	// Sanity check for safe mode only needs early-boot input samples.
	ksu_stop_input_hook_runtime();
	ksu_selinux_hide_handle_post_fs_data();

#ifdef CONFIG_KSU_SUSFS
	susfs_restore_boot();
#endif
}

extern void ext4_unregister_sysfs(struct super_block *sb);

int nuke_ext4_sysfs(const char *mnt)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);

	if (err) {
		pr_err("nuke path err: %d\n", err);
		return err;
	}

	if (strcmp(path.dentry->d_inode->i_sb->s_type->name, "ext4") != 0) {
		pr_debug("nuke but module aren't mounted\n");
		path_put(&path);
		return -EINVAL;
	}

	ext4_unregister_sysfs(path.dentry->d_inode->i_sb);
	path_put(&path);
	return 0;
}

void on_module_mounted(void)
{
	pr_debug("on_module_mounted!\n");
	ksu_module_mounted = true;
}

void on_boot_completed(void)
{
	ksu_boot_completed = true;
	pr_debug("on_boot_completed!\n");
	track_throne(true);
	ksu_selinux_hide_drop_backup_if_unused();
	ksu_avc_spoof_late_init();
}

#ifdef CONFIG_KSU_SUSFS
static bool susfs_boot_restored __read_mostly = false;

/* ── SUSFS boot restore: apply built-in default rules ────────── */
static void susfs_restore_boot(void)
{
	int i;

	{
		static const char * const paths[] = {
			"/system/bin/su",
			"/odm/bin/su",
			"/data/adb/ksu/su",
			"/system/addon.d",
			"/system/build.prop",
			"/data/adb/modules",
			"/data/adb/ksu-pdeath",
			"/data/adb/ksu/.allowlist",
			"/data/adb/ksu/.feature_config",
			NULL,
		};
		for (i = 0; paths[i]; i++)
			susfs_add_sus_path_kernel(paths[i]);
	}
	{
		static const char * const maps[] = {
			"/data/adb/",
			NULL,
		};
		for (i = 0; maps[i]; i++)
			susfs_mark_inode_sus_map(maps[i]);
	}
	{
		static const char * const mounts[] = {
			"/vendor",
			"/odm",
			NULL,
		};
		for (i = 0; mounts[i]; i++)
			susfs_add_sus_mount_kernel(mounts[i]);
	}

	susfs_set_uname_kernel("4.19.304", "Default/4.19");

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	susfs_set_log(false);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	WRITE_ONCE(susfs_hide_sus_mnts_for_all_procs, true);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_AVC_LOG_SPOOFING
	WRITE_ONCE(susfs_is_avc_log_spoofing_enabled, true);
#endif

	susfs_restore_properties();

	susfs_boot_restored = true;
	pr_info("susfs: boot restore complete\n");
}

int susfs_is_boot_restored(void)
{
	return susfs_boot_restored ? 1 : 0;
}

/* Mark an inode as SUS_MAP (kernel-safe, no __user) */
static int susfs_mark_inode_sus_map(const char *path)
{
	struct path p;
	struct inode *inode;
	int err;

	err = kern_path(path, 0, &p);
	if (err)
		return err;
	inode = d_inode(p.dentry);
	spin_lock(&inode->i_lock);
	inode->i_state |= INODE_STATE_SUS_MAP;
	spin_unlock(&inode->i_lock);
	path_put(&p);
	return 0;
}
#endif /* CONFIG_KSU_SUSFS */
