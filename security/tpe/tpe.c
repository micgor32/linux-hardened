// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>

#include "tpe.h"

static int tpe_enforce = IS_ENABLED(CONFIG_SECURITY_TPE);

#ifdef CONFIG_SYSCTL

static int proc_handler_tpe(const struct ctl_table *table, int dir,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	if (SYSCTL_USER_TO_KERN(dir))
		return -EINVAL;
	return proc_dointvec_minmax(table, dir, buffer, lenp, ppos);
}

static const struct ctl_table tpe_sysctl_table[] = {
	{
		.procname       = "tpe_enforce",
		.data           = &tpe_enforce,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_handler_tpe,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
};
#endif

static int tpe_allow(const struct file *file)
{
		struct inode *inode = d_backing_inode(file->f_path.dentry->d_parent);
		struct inode *file_inode = d_backing_inode(file->f_path.dentry);
		char *msg = NULL;

		if (!tpe_enforce)
				return 0;

		if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
				return 0;

		// TODO: add option for trusted groups
		if (!uid_eq(inode->i_uid, GLOBAL_ROOT_UID))
				msg = "file in not-root-owned directory";
		else if (inode->i_mode & S_IWOTH)
				msg = "file in world-writable directory";
		else if ((inode->i_mode & S_IWGRP) && !gid_eq(inode->i_gid, GLOBAL_ROOT_GID))
				msg = "file in group-writable directory";
		else if (file_inode->i_mode & S_IWOTH)
				msg = "file is world-writable";

		if (msg)
				goto out_fail;

		return 0;


out_fail:
		pr_warn("%s\n", msg);
		return -EPERM;
}

int tpe_bprm_creds_for_exec(struct linux_binprm *bprm)
{
		pr_info("lets'see");
		return tpe_allow(bprm->file);
}

static const struct lsm_id tpe_lsmid = {
		.name = "tpe",
		.id = LSM_ID_TPE,
};

static struct security_hook_list tpe_hooks[] __ro_after_init = {
		LSM_HOOK_INIT(bprm_creds_for_exec, tpe_bprm_creds_for_exec),
};

static int __init tpe_init(void)
{
		pr_info("TPE: starting.\n");
#ifdef CONFIG_SYSCTL
		if (!register_sysctl("kernel/tpe", tpe_sysctl_table))
				pr_notice("sysctl registration failed!\n");
#endif
		security_add_hooks(tpe_hooks, ARRAY_SIZE(tpe_hooks), &tpe_lsmid);
		return 0;
}

DEFINE_LSM(tpe) = {
		.id = &tpe_lsmid,
		.init = tpe_init,
};
