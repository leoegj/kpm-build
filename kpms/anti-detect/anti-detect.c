/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * anti-detect: Hide emulator files and frida-server from apps
 * - Blocks stat/access/readlink with ENOENT
 * - Filters directory listings (getdents64) to remove matching entries
 * - Hides frida-server process from /proc scans
 * - Allows openat (needed for GPU rendering via goldfish_pipe)
 * - Only affects regular apps (uid >= 10000)
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <syscall.h>
#include <kputils.h>
#include <kallsyms.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include "../common/kpm_demo_helpers.h"

KPM_MODULE_INFO("anti-detect",
                "1.4.0",
                "GPL v2",
                "wwb",
                "Hide emulator files, frida-server process, frida unix sockets, and KernelPatch presence from apps");

/* anti-detect-supercall.c */
extern int supercall_guard_init(const char *superkey);
extern void supercall_guard_exit(void);

#define AID_APP_START 10000
#define FILENAME_BUF_SIZE 256

#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

/* Resolved kernel functions */
static void *(*kfn_kmalloc)(size_t size, unsigned int flags);
static void (*kfn_kfree)(const void *ptr);
static unsigned long (*kfn_copy_from_user)(void *to, const void __user *from, unsigned long n);

/* GFP_KERNEL = 0xcc0 on most kernels */
#define GFP_KERNEL_VAL 0xcc0

struct linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

/* Forward declaration - full struct not needed with get_task_comm */
struct task_struct;

/* Resolved by kallsyms */
static struct task_struct *(*kfn_find_task_by_vpid)(pid_t nr);
static void (*kfn_get_task_comm)(char *to, struct task_struct *task);

/* Check if a PID entry corresponds to a hidden process */
static int should_hide_proc(const char *name)
{
    pid_t nr;
    struct task_struct *task;

    /* Only check numeric entries (PID directories) */
    if (!name || name[0] < '0' || name[0] > '9')
        return 0;

    nr = 0;
    while (*name >= '0' && *name <= '9') {
        nr = nr * 10 + (*name - '0');
        name++;
    }
    if (*name != '\0')
        return 0; /* not a pure numeric PID */

    if (!kfn_find_task_by_vpid || !kfn_get_task_comm)
        return 0;

    task = kfn_find_task_by_vpid(nr);
    if (!task)
        return 0;

    /* Use get_task_comm to safely read task->comm */
    char comm[16];
    kfn_get_task_comm(comm, task);
    comm[15] = '\0';

    /* Match "frida" in task name (catches frida-server, re.frida.helper) */
    return strstr(comm, "frida") != NULL;
}

static int should_hide(const char *name)
{
    return strstr(name, "goldfish_") != NULL;
}

/* Block stat/access/readlink for hidden files */
static void before_stat_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (uid < AID_APP_START) return;

    const char __user *ufilename = (const char __user *)syscall_argn(args, 1);
    char buf[FILENAME_BUF_SIZE];
    long len = compat_strncpy_from_user(buf, ufilename, sizeof(buf));
    if (len <= 0) return;

    if (should_hide(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

/* Pre-scan user dirent buffer for hidden entries without allocating */
static int getdents_has_hidden(char __user *ubuf, long len)
{
    unsigned short reclen;
    char name[FILENAME_BUF_SIZE];
    char __user *pos = ubuf;
    char __user *end = ubuf + len;

    while (pos < end) {
        if (kfn_copy_from_user(&reclen, pos + offsetof(struct linux_dirent64, d_reclen), 2))
            return 0;
        if (reclen == 0 || pos + reclen > end) break;
        long nlen = compat_strncpy_from_user(name, pos + offsetof(struct linux_dirent64, d_name), sizeof(name));
        if (nlen > 0 && (should_hide(name) || should_hide_proc(name)))
            return 1;
        pos += reclen;
    }
    return 0;
}

/* Filter directory listings to remove hidden entries */
static void after_getdents64(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (uid < AID_APP_START) return;

    long ret = (long)args->ret;
    if (ret <= 0) return;

    char __user *ubuf = (char __user *)syscall_argn(args, 1);

    /* Fast path: no hidden entries, skip allocation entirely */
    if (!getdents_has_hidden(ubuf, ret))
        return;

    /* Skip filtering for huge buffers to avoid unbounded kmalloc */
    if (ret > 256 * 1024)
        return;

    char *kbuf = kfn_kmalloc(ret, GFP_KERNEL_VAL);
    if (!kbuf) return;

    if (kfn_copy_from_user(kbuf, ubuf, ret)) {
        kfn_kfree(kbuf);
        return;
    }

    char *src = kbuf;
    char *end = kbuf + ret;
    char *dst = kbuf;
    long new_ret = 0;

    while (src < end) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)src;
        unsigned short reclen = d->d_reclen;
        if (reclen == 0 || src + reclen > end) break;

        if (!should_hide(d->d_name) && !should_hide_proc(d->d_name)) {
            if (dst != src)
                memmove(dst, src, reclen);
            dst += reclen;
            new_ret += reclen;
        }
        src += reclen;
    }

    if (new_ret != ret) {
        if (new_ret == 0 || compat_copy_to_user(ubuf, kbuf, new_ret) == new_ret)
            args->ret = new_ret;
    }

    kfn_kfree(kbuf);
}

/* Filter read output for @frida unix sockets in /proc/net/unix */
#define SCAN_BUF_SIZE 16384

static void after_read_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (uid < AID_APP_START) return;

    long ret = (long)args->ret;
    if (ret <= 0) return;

    char __user *ubuf = (char __user *)syscall_argn(args, 1);
    if (!ubuf) return;

    /* Only scan reads up to SCAN_BUF_SIZE */
    long scan_len = ret;
    if (scan_len > SCAN_BUF_SIZE)
        scan_len = SCAN_BUF_SIZE;

    char *kbuf = kfn_kmalloc(scan_len, GFP_KERNEL_VAL);
    if (!kbuf) return;

    if (kfn_copy_from_user(kbuf, ubuf, scan_len)) {
        kfn_kfree(kbuf);
        return;
    }

    /* Search for "@frida" in the buffer and null it out */
    char *pos = kbuf;
    char *end = kbuf + scan_len - 7;  /* need at least 7 bytes for "@/frida" */
    int modified = 0;

    while (pos < end) {
        /* Look for '@/frida' (frida unix socket naming) */
        if (pos[0] == '@' && pos[1] == '/' && pos[2] == 'f' &&
            pos[3] == 'r' && pos[4] == 'i' && pos[5] == 'd' && pos[6] == 'a') {
            /* Find the end of this line (null or newline) */
            char *line_end = pos;
            while (line_end < kbuf + scan_len && *line_end != '\n' && *line_end != '\0')
                line_end++;
            /* Null out the entire line */
            memset(pos, 0, line_end - pos);
            modified = 1;
            pr_err("anti-detect: filtered @/frida in read buffer\n");
            pos = line_end;
        } else {
            pos++;
        }
    }

    if (modified) {
        if (compat_copy_to_user(ubuf, kbuf, scan_len) == 0)
            ; /* successfully updated user buffer */
        else
            pr_err("anti-detect: copy_to_user failed\n");
    }

    kfn_kfree(kbuf);
}

static int resolve_symbols(void)
{
    /* kmalloc - try multiple names */
    kfn_kmalloc = (typeof(kfn_kmalloc))kallsyms_lookup_name("kmalloc");
    if (!kfn_kmalloc)
        kfn_kmalloc = (typeof(kfn_kmalloc))kallsyms_lookup_name("__kmalloc");
    if (!kfn_kmalloc) {
        pr_err("anti-detect: kmalloc not found\n");
        return -1;
    }

    /* kfree */
    kfn_kfree = (typeof(kfn_kfree))kallsyms_lookup_name("kfree");
    if (!kfn_kfree) {
        pr_err("anti-detect: kfree not found\n");
        return -1;
    }

    /* copy_from_user - try multiple names */
    kfn_copy_from_user = (typeof(kfn_copy_from_user))kallsyms_lookup_name("_copy_from_user");
    if (!kfn_copy_from_user)
        kfn_copy_from_user = (typeof(kfn_copy_from_user))kallsyms_lookup_name("copy_from_user");
    if (!kfn_copy_from_user)
        kfn_copy_from_user = (typeof(kfn_copy_from_user))kallsyms_lookup_name("__arch_copy_from_user");
    if (!kfn_copy_from_user) {
        pr_err("anti-detect: copy_from_user not found\n");
        return -1;
    }

    pr_info("anti-detect: symbols resolved: kmalloc=%px kfree=%px copy_from_user=%px\n",
            kfn_kmalloc, kfn_kfree, kfn_copy_from_user);

    /* find_task_by_vpid - for hiding processes by PID */
    kfn_find_task_by_vpid = (typeof(kfn_find_task_by_vpid))kallsyms_lookup_name("find_task_by_vpid");

    /* get_task_comm - safe way to read task comm */
    kfn_get_task_comm = (typeof(kfn_get_task_comm))kallsyms_lookup_name("get_task_comm");

    if (!kfn_find_task_by_vpid || !kfn_get_task_comm) {
        pr_warn("anti-detect: find_task_by_vpid/get_task_comm not found, process hiding disabled\n");
    } else {
        pr_info("anti-detect: process hiding ready\n");
    }

    return 0;
}

struct syscall_hook {
    int nr;
    int narg;
    void *before;
    void *after;
};

static struct syscall_hook hooks[] = {
    /* stat/access - block with ENOENT */
    { __NR_faccessat,     3, before_stat_syscall, 0 },
    { __NR_faccessat2,    4, before_stat_syscall, 0 },
    { __NR3264_fstatat,   4, before_stat_syscall, 0 },
    { __NR_statx,         5, before_stat_syscall, 0 },
    { __NR_readlinkat,    4, before_stat_syscall, 0 },
    /* getdents64 - filter output */
    { __NR_getdents64,    3, 0, after_getdents64 },
    /* read - filter @frida from /proc/net/unix */
    { __NR_read,          3, 0, after_read_syscall },
};

#define NUM_HOOKS (sizeof(hooks) / sizeof(hooks[0]))

static int hooks_installed;

static long anti_detect_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("anti-detect: loading...\n");

    if (resolve_symbols())
        return -1;

    for (hooks_installed = 0; hooks_installed < NUM_HOOKS; hooks_installed++) {
        const struct syscall_hook *h = &hooks[hooks_installed];
        hook_err_t err = hook_syscalln(h->nr, h->narg, h->before, h->after, 0);
        if (err) {
            pr_err("anti-detect: hook syscall %d failed: %d\n", h->nr, err);
            goto rollback;
        }
    }

    pr_info("anti-detect: %d hooks installed\n", hooks_installed);

    /* args = superkey for supercall guard (optional) */
    if (supercall_guard_init(args))
        goto rollback_supercall;

    return 0;

rollback_supercall:
    supercall_guard_exit();
rollback:
    while (hooks_installed-- > 0) {
        const struct syscall_hook *h = &hooks[hooks_installed];
        unhook_syscalln(h->nr, h->before, h->after);
    }
    return -1;
}

static long anti_detect_exit(void *__user reserved)
{
    supercall_guard_exit();
    int i;
    for (i = NUM_HOOKS; i-- > 0;) {
        const struct syscall_hook *h = &hooks[i];
        unhook_syscalln(h->nr, h->before, h->after);
    }
    pr_info("anti-detect: unloaded\n");
    return 0;
}

KPM_INIT(anti_detect_init);
KPM_EXIT(anti_detect_exit);
