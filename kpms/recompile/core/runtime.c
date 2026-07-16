/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/printk.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <syscall.h>

#include "../recompile_internal.h"

static void do_page_fault_before_impl(hook_fargs3_t *args, void *udata)
{
    unsigned long far = (unsigned long)args->arg0;
    unsigned int esr = (unsigned int)(unsigned long)args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    struct recompile_mapping *m;
    void *mm;
    unsigned long offset;

    if (!is_el0_instruction_abort(esr))
        return;

    mm = *(void **)((char *)current + task_struct_offset.active_mm_offset);
    if (!mm)
        return;

    if (is_permission_fault(esr)) {
        m = rc_find_mapping(mm, far);
        if (!m)
            return;

        offset = far & ~PAGE_MASK;
        regs->pc = m->recomp_page + offset;
        rc_mapping_put(m);
        atomic_inc(&stat_fault_redirect);

        args->ret = 0;
        args->skip_origin = true;
    } else if (is_translation_fault(esr)) {
        m = rc_find_mapping(mm, far);
        if (!m)
            return;

        spin_lock(&global_lock);
        if (!m->pte_stripped && !m->dead) {
            args->local.data0 = (unsigned long)m;
            args->local.data1 = far;
            spin_unlock(&global_lock);
            return;
        }
        spin_unlock(&global_lock);
        rc_mapping_put(m);
    }
}

static void do_page_fault_after_impl(hook_fargs3_t *args, void *udata)
{
    struct recompile_mapping *m = (void *)args->local.data0;
    unsigned long far = args->local.data1;
    unsigned long page_addr;
    unsigned long offset;
    void *mm;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    u64 orig_pte;
    unsigned long pfn;
    int ret;

    if (!m)
        return;

    page_addr = far & PAGE_MASK;
    offset = far & ~PAGE_MASK;
    mm = m->mm;

    /*
     * We're in fault handler context where mmap_lock may not be held.
     * Use NULL vma to avoid find_vma() which requires mmap_lock.
     * rc_try_strip_exec with NULL vma will skip ptep_modify_prot helpers
     * and directly write the PTE, which is safe in fault context.
     */
    ret = rc_try_strip_exec(mm, NULL, page_addr, &orig_pte, &pfn);
    if (ret == 0) {
        bool redirect_now = false;

        spin_lock(&global_lock);
        if (!m->dead) {
            m->pte_stripped = true;
            m->pte_original = orig_pte;
            m->pfn_original = pfn;
            redirect_now = true;
        }
        spin_unlock(&global_lock);

        /*
         * The original execute fault already pulled the page in. Redirect the
         * same faulting instruction now instead of relying on a second
         * permission fault on the just-stripped PTE.
         */
        if (redirect_now && regs) {
            regs->pc = m->recomp_page + offset;
            atomic_inc(&stat_fault_redirect);
        }
    }

    rc_mapping_put(m);
    args->local.data0 = 0;
}

void do_page_fault_before(hook_fargs3_t *args, void *udata)
{
    args->local.data0 = 0;
    if (atomic_read(&active_mapping_count) == 0)
        return;
    RC_HANDLER_ENTER();
    do_page_fault_before_impl(args, udata);
    RC_HANDLER_EXIT();
}

void do_page_fault_after(hook_fargs3_t *args, void *udata)
{
    if (!args->local.data0)
        return;
    RC_HANDLER_ENTER();
    do_page_fault_after_impl(args, udata);
    RC_HANDLER_EXIT();
}

static void exit_mmap_before_impl(hook_fargs1_t *args, void *udata)
{
    void *mm = (void *)args->arg0;
    int nr;

    if (!mm)
        return;

    nr = rc_teardown_mappings_for_mm(mm, "exit_mmap", true);
    if (nr > 0)
        pr_info("recompile: [exit_mmap] cleaned %d mappings for mm=%px\n", nr, mm);
}

void exit_mmap_before(hook_fargs1_t *args, void *udata)
{
    if (atomic_read(&active_mapping_count) == 0)
        return;
    RC_HANDLER_ENTER();
    exit_mmap_before_impl(args, udata);
    RC_HANDLER_EXIT();
}

void prctl_before(hook_fargs4_t *args, void *udata)
{
    int option = (int)syscall_argn(args, 0);
    unsigned long arg2 = syscall_argn(args, 1);
    unsigned long arg3 = syscall_argn(args, 2);
    unsigned long arg4 = syscall_argn(args, 3);
    void *mm;
    int ret;
    pid_t pid;

    if (option == PR_RECOMPILE_STATS) {
        int stat_id = (int)arg3;
        long val;
        switch (stat_id) {
        case RC_STAT_FORK_PAUSE:      val = atomic_read(&stat_fork_pause); break;
        case RC_STAT_FORK_RESUME:     val = atomic_read(&stat_fork_resume); break;
        case RC_STAT_FORK_SKIPPED:    val = atomic_read(&stat_fork_skipped); break;
        case RC_STAT_FAULT_REDIRECT:  val = atomic_read(&stat_fault_redirect); break;
        case RC_STAT_ACTIVE_MAPPINGS: val = atomic_read(&active_mapping_count); break;
        default: val = -22; break;
        }
        args->ret = val;
        args->skip_origin = 1;
        return;
    }

    if (option == PR_RECOMPILE_STATS_RESET) {
        atomic_set(&stat_fork_pause, 0);
        atomic_set(&stat_fork_resume, 0);
        atomic_set(&stat_fork_skipped, 0);
        atomic_set(&stat_fault_redirect, 0);
        args->ret = 0;
        args->skip_origin = 1;
        return;
    }

    if (option != PR_RECOMPILE_REGISTER && option != PR_RECOMPILE_RELEASE)
        return;

    RC_HANDLER_ENTER();

    pid = (pid_t)arg2;
    if (pid != 0) {
        args->ret = -95;
        args->skip_origin = 1;
        RC_HANDLER_EXIT();
        return;
    }

    mm = kfunc_get_task_mm(current);
    if (!mm) {
        args->ret = -3;
        args->skip_origin = 1;
        RC_HANDLER_EXIT();
        return;
    }

    switch (option) {
    case PR_RECOMPILE_REGISTER:
        ret = rc_do_register(mm, arg3, arg4);
        break;
    case PR_RECOMPILE_RELEASE:
        ret = rc_do_release(mm, arg3);
        break;
    default:
        ret = -22;
        break;
    }

    kfunc_mmput(mm);
    args->ret = ret;
    args->skip_origin = 1;
    RC_HANDLER_EXIT();
}
