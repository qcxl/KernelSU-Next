// SPDX-License-Identifier: GPL-2.0
/*
 * feature/selinux_hide.c — 统一版 SELinux hide (4.19)
 *
 * 合并版本 A (dev: ksu_patch_text + ksu_lsm_hook + fake_status) 和
 * 版本 B (注入: 过滤模式 + WRITE_ONCE + 直接 security_hook_heads 操作) 的最佳部分。
 *
 * 4.19 适配：
 *   - 过滤模式代替 backup_sepolicy (4.19 不支持 struct selinux_policy)
 *   - WRITE_ONCE 写 write_op[] (4.19 不支持 ksu_patch_text — 仅 dev 分支有此 API)
 *   - 去掉 write_op[SEL_ENFORCE] 钩子 (LineageOS 4.19 恒为 NULL)
 *   - init 时不自动启用 (toggle 才激活)
 *   - Manager UID 豁免 (GHA 工作流中原有的注入步骤, 现内置)
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/kallsyms.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "selinux_hide.h"
#include "policy/feature.h"
#include "manager/manager_identity.h"
#include "klog.h"
#include "hook/patch_memory.h"
#include "hook/lsm_hook.h"
#include "selinux/selinux.h"

/* ============= 常量 ============= */

#define KSU_DOMAIN_TAG   ":ksu:"
#define KSU_DOMAIN_TAG2  ":ksu_"
#define KSU_DOMAIN_FULL  "u:r:ksu:s0"

#ifndef SIMPLE_TRANSACTION_LIMIT
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(ssize_t))
#endif

/* ============= SELinux inode 编号 ============= */

enum sel_inos {
	SEL_ROOT_INO = 2,
	SEL_LOAD,
	SEL_ENFORCE,
	SEL_CONTEXT,
	SEL_ACCESS,
	SEL_CREATE,
	SEL_RELABEL,
	SEL_USER,
	SEL_POLICYVERS,
	SEL_COMMIT_BOOLS,
	SEL_MLS,
	SEL_DISABLE,
	SEL_MEMBER,
	SEL_CHECKREQPROT,
	SEL_COMPAT_NET,
	SEL_REJECT_UNKNOWN,
	SEL_DENY_UNKNOWN,
	SEL_STATUS,
	SEL_POLICY,
	SEL_VALIDATE_TRANS,
	SEL_INO_NEXT,
};

/* ============= 类型定义 ============= */

typedef ssize_t (*write_op_fn)(struct file *file, char *buf, size_t size);
typedef int (*setprocattr_fn)(const char *name, void *value, size_t size);

static int __nocfi my_setprocattr(const char *name, void *value, size_t size);
struct ksu_lsm_hook selinux_setprocattr_hook = KSU_LSM_HOOK_INIT(setprocattr, "selinux_setprocattr", my_setprocattr, 0);

/* ============= 全局状态 ============= */

static DEFINE_MUTEX(selinux_hide_mutex);
static bool ksu_selinux_hide_enabled __read_mostly = false;
static bool ksu_selinux_hide_running __read_mostly = false;
static write_op_fn *selinux_write_op = NULL;
static write_op_fn *context_write_slot = NULL;
static write_op_fn *access_write_slot = NULL;
static write_op_fn orig_context_write = NULL;
static write_op_fn orig_access_write = NULL;

/* ============= 辅助函数 ============= */

static bool buf_contains(const char *buf, size_t size, const char *needle)
{
	size_t needle_len;

	if (!buf || !needle || size == 0)
		return false;
	needle_len = strlen(needle);
	if (needle_len == 0 || needle_len > size)
		return false;
	return strnstr(buf, needle, size) != NULL;
}

static bool buf_mentions_ksu(const char *buf, size_t size)
{
	return buf_contains(buf, size, KSU_DOMAIN_TAG) ||
	       buf_contains(buf, size, KSU_DOMAIN_TAG2) ||
	       buf_contains(buf, size, KSU_DOMAIN_FULL);
}

/* ============= my_write_context (过滤模式) ============= */

static ssize_t my_write_context(struct file *file, char *buf, size_t size)
{
	if (likely(current_uid().val >= 10000 &&
		   ksu_selinux_hide_enabled &&
		   ksu_selinux_hide_running &&
		   current_uid().val != ksu_get_manager_appid())) {
		if (buf_mentions_ksu(buf, size))
			return -EINVAL;
	}
	return orig_context_write(file, buf, size);
}

/* ============= my_write_access (过滤模式) ============= */

static ssize_t my_write_access(struct file *file, char *buf, size_t size)
{
	if (likely(current_uid().val >= 10000 &&
		   ksu_selinux_hide_enabled &&
		   ksu_selinux_hide_running &&
		   current_uid().val != ksu_get_manager_appid())) {
		if (buf_mentions_ksu(buf, size)) {
			return scnprintf(buf, SIMPLE_TRANSACTION_LIMIT,
					 "%x %x %x %x %u %x",
					 0, 0xffffffff, 0, 0xffffffff, 0, 0);
		}
	}
	return orig_access_write(file, buf, size);
}

/* ============= my_setprocattr (通过 ksu_lsm_hook 基础设施) ============= */

static int __nocfi my_setprocattr(const char *name, void *value, size_t size)
{
	if (ksu_selinux_hide_enabled &&
	    ksu_selinux_hide_running &&
	    current_uid().val >= 10000 &&
	    current_uid().val != ksu_get_manager_appid()) {
		if (name && !strcmp(name, "current")) {
			if (value && buf_mentions_ksu((const char *)value, size))
				return -EACCES;
		}
	}
	return ((setprocattr_fn)selinux_setprocattr_hook.original)(name, value, size);
}

/* ============= hook / unhook 安装 ============= */

static void hook_write_ops(void)
{
	write_op_fn my;
	int ret;

	if (selinux_write_op)
		return;

	selinux_write_op = (write_op_fn *)kallsyms_lookup_name("write_op");
	if (!selinux_write_op) {
		pr_err("selinux_hide: write_op not found\n");
		return;
	}

	context_write_slot = &selinux_write_op[SEL_CONTEXT];
	orig_context_write = *context_write_slot;
	if (!orig_context_write) {
		pr_warn("selinux_hide: write_op[SEL_CONTEXT] is NULL, skipping\n");
		context_write_slot = NULL;
	} else {
		my = my_write_context;
		ret = ksu_patch_text(context_write_slot, &my, sizeof(my),
				     KSU_PATCH_TEXT_FLUSH_DCACHE);
		if (ret) {
			pr_err("selinux_hide: patch_text context_write err: %d\n",
			       ret);
			context_write_slot = NULL;
			orig_context_write = NULL;
		}
	}

	access_write_slot = &selinux_write_op[SEL_ACCESS];
	orig_access_write = *access_write_slot;
	if (!orig_access_write) {
		pr_warn("selinux_hide: write_op[SEL_ACCESS] is NULL, skipping\n");
		access_write_slot = NULL;
	} else {
		my = my_write_access;
		ret = ksu_patch_text(access_write_slot, &my, sizeof(my),
				     KSU_PATCH_TEXT_FLUSH_DCACHE);
		if (ret) {
			pr_err("selinux_hide: patch_text access_write err: %d\n",
			       ret);
			access_write_slot = NULL;
			orig_access_write = NULL;
		}
	}
}

static void hook_selinux_setprocattr(void)
{
	int ret;

	ret = ksu_lsm_hook(&selinux_setprocattr_hook);
	if (ret)
		pr_err("selinux_hide: hook selinux_setprocattr err: %d\n", ret);
	else
		pr_info("selinux_hide: selinux_setprocattr hooked\n");
}

static void unhook_write_ops(void)
{
	int ret;

	if (context_write_slot) {
		if (*context_write_slot == my_write_context) {
			write_op_fn orig = orig_context_write;
			ret = ksu_patch_text(context_write_slot, &orig,
					     sizeof(orig),
					     KSU_PATCH_TEXT_FLUSH_DCACHE);
			if (ret)
				pr_err("selinux_hide: restore context_write err: %d\n",
				       ret);
		}
		context_write_slot = NULL;
		orig_context_write = NULL;
	}
	if (access_write_slot) {
		if (*access_write_slot == my_write_access) {
			write_op_fn orig = orig_access_write;
			ret = ksu_patch_text(access_write_slot, &orig,
					     sizeof(orig),
					     KSU_PATCH_TEXT_FLUSH_DCACHE);
			if (ret)
				pr_err("selinux_hide: restore access_write err: %d\n",
				       ret);
		}
		access_write_slot = NULL;
		orig_access_write = NULL;
	}
}

static void unhook_selinux_setprocattr(void)
{
	ksu_lsm_unhook(&selinux_setprocattr_hook);
}

/* ============= enable / disable / unhook ============= */

static int ksu_selinux_hide_enable(void)
{
	pr_info("selinux_hide: enabling\n");
	hook_write_ops();
	hook_selinux_setprocattr();
	return 0;
}

static void ksu_selinux_hide_unhook(void)
{
	pr_info("selinux_hide: unhooking\n");
	unhook_write_ops();
	unhook_selinux_setprocattr();
}

static void ksu_selinux_hide_disable(void)
{
	pr_info("selinux_hide: disabling\n");
	ksu_selinux_hide_unhook();
}

/* ============= Feature handler (get/set) ============= */

static int selinux_hide_feature_get(u64 *value)
{
	*value = ksu_selinux_hide_enabled ? 1 : 0;
	return 0;
}

static int selinux_hide_feature_set(u64 value)
{
	bool enable = value != 0;
	int ret = 0;

	pr_info("selinux_hide: set to %d\n", enable);

	mutex_lock(&selinux_hide_mutex);
	ksu_selinux_hide_enabled = enable;
	if (enable) {
		if (!ksu_selinux_hide_running) {
			ret = ksu_selinux_hide_enable();
			if (!ret)
				ksu_selinux_hide_running = true;
			else
				ksu_selinux_hide_enabled = false;
		}
	} else {
		if (ksu_selinux_hide_running) {
			ksu_selinux_hide_disable();
			ksu_selinux_hide_running = false;
		}
	}
	mutex_unlock(&selinux_hide_mutex);
	return ret;
}

static const struct ksu_feature_handler selinux_hide_handler = {
	.feature_id = KSU_FEATURE_SELINUX_HIDE,
	.name = "selinux_hide",
	.get_handler = selinux_hide_feature_get,
	.set_handler = selinux_hide_feature_set,
};

/* ============= set_enforce feature handler ============= */

static int enforce_feature_get(u64 *value)
{
	*value = getenforce() ? 1 : 0;
	return 0;
}

static int enforce_feature_set(u64 value)
{
	bool enforce = value != 0;

	setenforce(enforce);
	if (getenforce() == enforce)
		return 0;

	return -EOPNOTSUPP;
}

static const struct ksu_feature_handler enforce_handler = {
	.feature_id = KSU_FEATURE_SET_SELINUX_ENFORCE,
	.name = "set_selinux_enforce",
	.get_handler = enforce_feature_get,
	.set_handler = enforce_feature_set,
};

/* ============= 公开 API ============= */

void __init ksu_selinux_hide_init(void)
{
	int ret;

	ret = ksu_register_feature_handler(&selinux_hide_handler);
	if (ret)
		pr_err("selinux_hide: failed to register feature handler: %d\n", ret);

	ret = ksu_register_feature_handler(&enforce_handler);
	if (ret)
		pr_err("selinux_hide: failed to register enforce handler: %d\n", ret);

	pr_info("selinux_hide: initialized (toggle to activate)\n");
}

void __exit ksu_selinux_hide_exit(void)
{
	mutex_lock(&selinux_hide_mutex);
	if (ksu_selinux_hide_running) {
		ksu_selinux_hide_disable();
		ksu_selinux_hide_running = false;
	}
	ksu_selinux_hide_enabled = false;
	mutex_unlock(&selinux_hide_mutex);

	ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);
	ksu_unregister_feature_handler(KSU_FEATURE_SET_SELINUX_ENFORCE);
	pr_info("selinux_hide: exited\n");
}

void ksu_selinux_hide_drop_backup_if_unused(void)
{
	/* 过滤模式不依赖 backup_sepolicy, 无需操作 */
}

void ksu_selinux_hide_handle_second_stage(void)
{
	/* 过滤模式不需要第二阶段初始化 */
}

void ksu_selinux_hide_handle_post_fs_data(void)
{
	/* 过滤模式不需要 post-fs-data 初始化 */
}
