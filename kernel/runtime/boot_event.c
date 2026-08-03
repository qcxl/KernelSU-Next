#include "feature/selinux_hide.h"
#include "selinux/selinux.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <uapi/linux/fs.h>

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

	/* Move any modules left in staging (modules_update/) to active (modules/).
	 * This replaces handle_updated_modules() which never runs because
	 * init.rc exec injection is broken on this ROM (LineageOS 13). */
	susfs_apply_module_updates();

	susfs_boot_restored = true;
	pr_info("susfs: boot restore complete\n");
}

int susfs_is_boot_restored(void)
{
	return susfs_boot_restored ? 1 : 0;
}

/* Move module from staging to active:
 *   rename(modules_update/<name>/, modules/<name>/)
 * If the target exists, use RENAME_EXCHANGE to atomically swap,
 * leaving the old files in modules_update/<name/> for later cleanup
 * (the next module install will remove them via ensure_clean_dir). */
static int susfs_rename_one(const char *name, int namlen)
{
	char old_path[256], new_path[256];
	struct path old_p = {}, new_p = {}, modules_dir = {};
	struct dentry *new_dentry;
	int err;

	scnprintf(old_path, sizeof(old_path), "/data/adb/modules_update/%s", name);
	scnprintf(new_path, sizeof(new_path), "/data/adb/modules/%s", name);

	err = kern_path(old_path, 0, &old_p);
	if (err)
		return 0; /* source disappeared, skip */

	/* Ensure /data/adb/modules/ exists */
	if (kern_path("/data/adb/modules", 0, &modules_dir)) {
		path_put(&old_p);
		return 0;
	}

	/* lookup target dentry */
	new_dentry = lookup_one_len(name, modules_dir.dentry, namlen);
	if (IS_ERR(new_dentry)) {
		path_put(&modules_dir);
		path_put(&old_p);
		return 0;
	}

	/* Check if target exists */
	err = kern_path(new_path, 0, &new_p);
	if (!err) {
		/* Target exists → use RENAME_EXCHANGE to swap atomically */
		err = vfs_rename(old_p.dentry->d_parent->d_inode, old_p.dentry,
				 new_p.dentry->d_parent->d_inode, new_p.dentry,
				 NULL, RENAME_EXCHANGE);
		path_put(&new_p);
	} else {
		/* Target doesn't exist → simple rename */
		err = vfs_rename(old_p.dentry->d_parent->d_inode, old_p.dentry,
				 modules_dir.dentry->d_inode, new_dentry,
				 NULL, 0);
	}

	dput(new_dentry);
	path_put(&modules_dir);
	path_put(&old_p);
	return 0;
}

struct susfs_rename_ctx {
	struct dir_context ctx;
};

static int susfs_rename_actor(struct dir_context *ctx, const char *name,
			      int namlen, loff_t offset, u64 ino,
			      unsigned int d_type)
{
	if (name[0] == '.')
		return 0;
	/* DT_UNKNOWN on F2FS: just try the rename, susfs_rename_one
	 * will skip non-directories (kern_path fails for non-dirs). */
	susfs_rename_one(name, namlen);
	return 0;
}

void susfs_apply_module_updates(void)
{
	struct file *dir;
	struct susfs_rename_ctx rctx = {
		.ctx.actor = susfs_rename_actor,
	};

	dir = filp_open("/data/adb/modules_update/", O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(dir)) {
		pr_debug("susfs: modules_update not found (no staging)\n");
		return;
	}

	pr_debug("susfs: applying module updates...\n");
	iterate_dir(dir, &rctx.ctx);
	filp_close(dir, NULL);
	pr_debug("susfs: module updates done\n");
}
#endif /* CONFIG_KSU_SUSFS */
