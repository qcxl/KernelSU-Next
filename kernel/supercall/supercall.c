#include <linux/anon_inodes.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "util.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "selinux/selinux.h"

#include "sulog/event.h"
#include "runtime/ksud_boot.h"

#ifdef CONFIG_KPM
#include "kpm/kpm.h"
#endif

uint32_t ksuver_override = 0;

struct ksu_install_fd_tw {
	struct callback_head cb;
	int __user *outp;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
	pr_debug("ksu fd released\n");
#ifdef CONFIG_KSU_SUSFS
	/* Module install just completed (libksud.so closing its KSU fd).
	 * Move any staging modules to active immediately. */
	susfs_apply_module_updates();
#endif
	return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
#ifdef CONFIG_KSU_SUSFS
	/* SUSFS: exempt KSU-authorized processes from path hiding.
	 * Clear the hide bit ONLY for the manager app, the ksu domain (root
	 * shells) or uid 0, so that arbitrary apps which obtain the ksu fd
	 * via the public prctl/reboot magic (no uid check in the kprobe
	 * handler) cannot clear their own hide bit and then detect hidden
	 * root paths (e.g. /system/bin/su) -> bank/Hunter/Momo detection. */
	if (is_manager() || is_ksu_domain() || current_uid().val == 0)
		current->susfs_task_state = 0;
#endif
	return ksu_supercall_handle_ioctl(cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

	filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL,
				  O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
		pr_err("ksu_install_fd: failed to create anon inode file\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	fd_install(fd, filp);
	pr_debug("ksu fd installed: %d for pid %d\n", fd, current->pid);
	return fd;
}

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
	struct ksu_install_fd_tw *tw =
		container_of(cb, struct ksu_install_fd_tw, cb);
	int fd = ksu_install_fd();

	pr_debug("[%d] install ksu fd: %d\n", current->pid, fd);
	if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
		pr_err("install ksu fd reply err\n");
		ksu_close_fd(fd);
	}

	kfree(tw);
}

static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	unsigned int cmd = (unsigned int)PT_REGS_PARM3(real_regs);
	unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	unsigned long reply = (unsigned long)arg4;

	/* Check if this is a request to install KSU fd */
	if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
		struct ksu_install_fd_tw *tw;

		tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
		if (!tw)
			return 0;

		tw->outp = (int __user *)arg4;
		tw->cb.func = ksu_install_fd_tw_func;

		if (task_work_add(current, &tw->cb, TWA_RESUME)) {
			kfree(tw);
			pr_debug("install fd add task_work failed\n");
		}
	}

	if (magic2 == CHANGE_MANAGER_UID) {
		/* only root is allowed for this command */
		if (current_uid().val != 0)
			return 0;

		pr_debug("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)arg4, &reply,
					 sizeof(reply)))
				pr_debug("sys_reboot: reply fail\n");
		}

		return 0;
	}

	if (magic2 == GET_SULOG_DUMP_V2) {
		if (current_uid().val != 0)
			return 0;

		int ret = ksu_sulog_handle_compat_dump((void __user *)arg4);
		if (ret)
			return 0;

		if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
			return 0;
	}

	if (magic2 == CHANGE_KSUVER) {
		if (current_uid().val != 0)
			return 0;

		pr_debug("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;

		if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
			return 0;
	}

	// WARNING!!! triple ptr zone! ***
	// https://wiki.c2.com/?ThreeStarProgrammer
	if (magic2 == CHANGE_SPOOF_UNAME) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = { 0 };
		static char original_version_buf[65] = { 0 };

		// basically void * void __user * void __user *arg
		void __user **ppptr = (void __user **)arg4;

		// user pointer storage
		// init this as zero so this works on 32-on-64 compat (LE)
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		pr_debug("sys_reboot: ppptr: 0x%lx \n", (uintptr_t)ppptr);

		// arg here is ***, pull out user-space ** via copy_from_user
		if (copy_from_user(&u_pptr, ppptr, sizeof(u_pptr)))
			return 0;

		pr_debug("sys_reboot: u_pptr: 0x%lx \n", (uintptr_t)u_pptr);

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr,
				   sizeof(u_ptr)))
			return 0;

		pr_debug("sys_reboot: u_ptr: 0x%lx \n", (uintptr_t)u_ptr);

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr,
				      sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0';

		// for version
		if (strncpy_from_user(
			    version_buf,
			    (char __user *)(u_ptr + strlen(release_buf) + 1),
			    sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0';

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();
			// we save current version as the original before modifying
			strscpy(original_release_buf, u_curr->release,
				sizeof(original_release_buf));
			strscpy(original_version_buf, u_curr->version,
				sizeof(original_version_buf));
			pr_debug("sys_reboot: original uname saved: %s %s\n",
				 original_release_buf, original_version_buf);
		}

		// so user can reset
		if (!strcmp(release_buf, "default") ||
		    !strcmp(version_buf, "default")) {
			memcpy(release_buf, original_release_buf,
			       sizeof(release_buf));
			memcpy(version_buf, original_version_buf,
			       sizeof(version_buf));
		}

		pr_debug("sys_reboot: spoofing kernel to: %s - %s\n",
			 release_buf, version_buf);

		struct new_utsname *u = utsname();

		down_write(&uts_sem);
		strscpy(u->release, release_buf, sizeof(u->release));
		strscpy(u->version, version_buf, sizeof(u->version));
		up_write(&uts_sem);

		// we write our confirmation on **
		if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
			return 0;
	}

	return 0;
}

static struct kprobe reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = reboot_handler_pre,
};

/* prctl(0xDEADBEEF, 0xCAFEBABE, &fd, 0, 0) handler — seccomp-safe fd installation.
 * Unlike SYS_reboot (which gets SIGSYS from seccomp for app processes),
 * prctl is NOT blocked by seccomp, so untrusted_app processes can use
 * this path to get the ksu driver fd without being killed.
 */
static int prctl_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int option = (int)PT_REGS_PARM1(real_regs);
	unsigned long arg2 = PT_REGS_PARM2(real_regs);
	unsigned long arg3 = PT_REGS_PARM3(real_regs);

	/* prctl(0xDEADBEEF, 0xCAFEBABE, &fd_out, 0, 0) */
	if (option == KSU_INSTALL_MAGIC1 && arg2 == KSU_INSTALL_MAGIC2) {
		struct ksu_install_fd_tw *tw;
		int __user *outp = (int __user *)arg3;

		if (!outp)
			return 0;

		tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
		if (!tw)
			return 0;

		tw->outp = outp;
		tw->cb.func = ksu_install_fd_tw_func;

		if (task_work_add(current, &tw->cb, TWA_RESUME)) {
			kfree(tw);
			pr_debug("prctl: install fd add task_work failed\n");
		}
	}

	return 0;
}

static struct kprobe prctl_kp = {
	.symbol_name = PRCTL_SYMBOL,
	.pre_handler = prctl_handler_pre,
};

void __init ksu_supercalls_init(void)
{
	int rc;

	ksu_supercall_dump_commands();

	rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("reboot kprobe failed: %d\n", rc);
	} else {
		pr_debug("reboot kprobe registered successfully\n");
	}

	rc = register_kprobe(&prctl_kp);
	if (rc) {
		pr_err("prctl kprobe failed: %d\n", rc);
	} else {
		pr_debug("prctl kprobe registered successfully\n");
	}
}

void __exit ksu_supercalls_exit(void)
{
	unregister_kprobe(&reboot_kp);
	ksu_supercall_cleanup_state();
}
