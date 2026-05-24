/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TPE_H
#define _TPE_H

#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/security.h>

int tpe_bprm_creds_for_exec(struct linux_binprm *bprm);

#endif /* _TPE_H */
