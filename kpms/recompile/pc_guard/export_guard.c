/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/sched.h>
#include <asm/current.h>
#include <asm/processor.h>

#include "../recompile_internal.h"

static bool rc_rewrite_export_pc(void *mm, unsigned long pc, unsigned long *orig_pc)
{
    struct list_head *pos;
    unsigned long offset;
    bool found = false;

    if (!mm || !orig_pc)
        return false;
    if (atomic_read(&active_mapping_count) == 0)
        return false;

    spin_lock(&global_lock);
    list_for_each(pos, &mapping_list) {
        struct recompile_mapping *m =
            container_of(pos, struct recompile_mapping, list);

        if (m->mm != mm || m->dead)
            continue;
        if ((pc & PAGE_MASK) != m->recomp_page)
            continue;

        offset = pc & ~PAGE_MASK;
        *orig_pc = m->orig_page + offset;
        found = true;
        break;
    }
    spin_unlock(&global_lock);

    return found;
}

void rc_sanitize_regs_pc_shared(void *mm, struct pt_regs *regs, struct rc_saved_pc *saved)
{
    unsigned long orig_pc;

    saved->regs = NULL;
    saved->saved_pc = 0;

    if (!mm || !regs)
        return;
    if (!rc_rewrite_export_pc(mm, regs->pc, &orig_pc))
        return;

    saved->regs = regs;
    saved->saved_pc = regs->pc;
    regs->pc = orig_pc;
}

void rc_restore_sanitized_pc_shared(struct rc_saved_pc *saved)
{
    if (!saved->regs)
        return;
    saved->regs->pc = saved->saved_pc;
}

static bool rc_regset_is_prstatus(const struct rc_user_regset *regset)
{
    return regset && regset->core_note_type == NT_PRSTATUS;
}

static bool rc_view_set_is_prstatus(const struct rc_user_regset_view *view, unsigned int setno)
{
    if (!view || !view->regsets || setno >= view->n)
        return false;
    return rc_regset_is_prstatus(&view->regsets[setno]);
}

static bool rc_perf_reg_exports_pc(int idx)
{
    return idx == RC_PERF_REG_ARM64_PC || idx == RC_COMPAT_PERF_PC_REG;
}

static void rc_sanitize_target_task_pc(struct task_struct *target, struct rc_saved_pc *saved)
{
    if (!target) {
        saved->regs = NULL;
        saved->saved_pc = 0;
        return;
    }

    rc_sanitize_regs_pc_shared(rc_task_active_mm(target), task_pt_regs(target), saved);
}

void setup_sigframe_before(hook_fargs4_t *args, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)args->arg1;
    struct rc_saved_pc saved;

    args->local.data0 = 0;
    args->local.data1 = 0;

    if (atomic_read(&active_mapping_count) == 0 || !regs)
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_regs_pc_shared(rc_task_active_mm(current), regs, &saved);
    args->local.data0 = (unsigned long)saved.regs;
    args->local.data1 = saved.saved_pc;
    RC_HANDLER_EXIT();
}

void setup_sigframe_after(hook_fargs4_t *args, void *udata)
{
    struct rc_saved_pc saved;

    saved.regs = (struct pt_regs *)args->local.data0;
    saved.saved_pc = args->local.data1;
    if (!saved.regs)
        return;

    RC_HANDLER_ENTER();
    rc_restore_sanitized_pc_shared(&saved);
    RC_HANDLER_EXIT();
}

/*
 * do_signal hook - fallback when setup_sigframe is inlined (Linux 6.x+)
 * Signature: void do_signal(struct pt_regs *regs)
 */
/*
 * do_signal hook - fallback when setup_sigframe is inlined (Linux 6.x+)
 *
 * Key insight: do_signal modifies regs->pc to point to the signal handler.
 * We only sanitize PC for sigframe content, but must NOT restore it after
 * do_signal returns, because regs->pc now holds the signal handler address.
 *
 * For the sigframe itself: the kernel saves our sanitized PC (orig_page)
 * into sigframe before modifying regs->pc. When the handler calls sigreturn,
 * it restores this sanitized PC, then a fault redirects to recomp_page.
 *
 * So we only need to sanitize before, NOT restore after.
 */
void do_signal_before(hook_fargs1_t *args, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)args->arg0;
    struct rc_saved_pc saved;

    /* We don't use local storage since we don't restore in after hook */
    (void)args;
    (void)udata;

    if (atomic_read(&active_mapping_count) == 0 || !regs)
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_regs_pc_shared(rc_task_active_mm(current), regs, &saved);
    /* Note: we intentionally do NOT restore. sigframe now has orig_page,
     * and regs->pc will be overwritten with signal handler address. */
    RC_HANDLER_EXIT();
}

void do_signal_after(hook_fargs1_t *args, void *udata)
{
    /* Intentionally empty - see comment in do_signal_before */
    (void)args;
    (void)udata;
}

void compat_setup_sigframe_before(hook_fargs3_t *args, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)args->arg1;
    struct rc_saved_pc saved;

    args->local.data0 = 0;
    args->local.data1 = 0;

    if (atomic_read(&active_mapping_count) == 0 || !regs)
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_regs_pc_shared(rc_task_active_mm(current), regs, &saved);
    args->local.data0 = (unsigned long)saved.regs;
    args->local.data1 = saved.saved_pc;
    RC_HANDLER_EXIT();
}

void compat_setup_sigframe_after(hook_fargs3_t *args, void *udata)
{
    struct rc_saved_pc saved;

    saved.regs = (struct pt_regs *)args->local.data0;
    saved.saved_pc = args->local.data1;
    if (!saved.regs)
        return;

    RC_HANDLER_ENTER();
    rc_restore_sanitized_pc_shared(&saved);
    RC_HANDLER_EXIT();
}

void copy_regset_to_user_before(hook_fargs6_t *args, void *udata)
{
    struct rc_saved_pc saved;
    struct task_struct *target = (struct task_struct *)args->arg0;
    const struct rc_user_regset_view *view =
        (const struct rc_user_regset_view *)args->arg1;
    unsigned int setno = (unsigned int)(unsigned long)args->arg2;

    args->local.data0 = 0;
    args->local.data1 = 0;

    if (atomic_read(&active_mapping_count) == 0)
        return;
    if (!rc_view_set_is_prstatus(view, setno))
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_target_task_pc(target, &saved);
    args->local.data0 = (unsigned long)saved.regs;
    args->local.data1 = saved.saved_pc;
    RC_HANDLER_EXIT();
}

void copy_regset_to_user_after(hook_fargs6_t *args, void *udata)
{
    struct rc_saved_pc saved;

    saved.regs = (struct pt_regs *)args->local.data0;
    saved.saved_pc = args->local.data1;
    if (!saved.regs)
        return;

    RC_HANDLER_ENTER();
    rc_restore_sanitized_pc_shared(&saved);
    RC_HANDLER_EXIT();
}

void regset_get_before(hook_fargs4_t *args, void *udata)
{
    struct rc_saved_pc saved;
    struct task_struct *target = (struct task_struct *)args->arg0;
    const struct rc_user_regset *regset =
        (const struct rc_user_regset *)args->arg1;

    args->local.data0 = 0;
    args->local.data1 = 0;

    if (atomic_read(&active_mapping_count) == 0)
        return;
    if (!rc_regset_is_prstatus(regset))
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_target_task_pc(target, &saved);
    args->local.data0 = (unsigned long)saved.regs;
    args->local.data1 = saved.saved_pc;
    RC_HANDLER_EXIT();
}

void regset_get_after(hook_fargs4_t *args, void *udata)
{
    struct rc_saved_pc saved;

    saved.regs = (struct pt_regs *)args->local.data0;
    saved.saved_pc = args->local.data1;
    if (!saved.regs)
        return;

    RC_HANDLER_ENTER();
    rc_restore_sanitized_pc_shared(&saved);
    RC_HANDLER_EXIT();
}

void regset_get_alloc_before(hook_fargs4_t *args, void *udata)
{
    regset_get_before(args, udata);
}

void regset_get_alloc_after(hook_fargs4_t *args, void *udata)
{
    regset_get_after(args, udata);
}

void perf_instruction_pointer_before(hook_fargs1_t *args, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)args->arg0;
    struct rc_saved_pc saved;

    args->local.data0 = 0;
    args->local.data1 = 0;

    if (atomic_read(&active_mapping_count) == 0 || !regs)
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_regs_pc_shared(rc_task_active_mm(current), regs, &saved);
    args->local.data0 = (unsigned long)saved.regs;
    args->local.data1 = saved.saved_pc;
    RC_HANDLER_EXIT();
}

void perf_instruction_pointer_after(hook_fargs1_t *args, void *udata)
{
    struct rc_saved_pc saved;

    saved.regs = (struct pt_regs *)args->local.data0;
    saved.saved_pc = args->local.data1;
    if (!saved.regs)
        return;

    RC_HANDLER_ENTER();
    rc_restore_sanitized_pc_shared(&saved);
    RC_HANDLER_EXIT();
}

void perf_reg_value_before(hook_fargs2_t *args, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)args->arg0;
    int idx = (int)(unsigned long)args->arg1;
    struct rc_saved_pc saved;

    args->local.data0 = 0;
    args->local.data1 = 0;

    if (atomic_read(&active_mapping_count) == 0 || !regs)
        return;
    if (!rc_perf_reg_exports_pc(idx))
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_regs_pc_shared(rc_task_active_mm(current), regs, &saved);
    args->local.data0 = (unsigned long)saved.regs;
    args->local.data1 = saved.saved_pc;
    RC_HANDLER_EXIT();
}

void perf_reg_value_after(hook_fargs2_t *args, void *udata)
{
    perf_instruction_pointer_after((hook_fargs1_t *)args, udata);
}

void perf_callchain_user_before(hook_fargs2_t *args, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)args->arg1;
    struct rc_saved_pc saved;

    args->local.data0 = 0;
    args->local.data1 = 0;

    if (atomic_read(&active_mapping_count) == 0 || !regs)
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_regs_pc_shared(rc_task_active_mm(current), regs, &saved);
    args->local.data0 = (unsigned long)saved.regs;
    args->local.data1 = saved.saved_pc;
    RC_HANDLER_EXIT();
}

void perf_callchain_user_after(hook_fargs2_t *args, void *udata)
{
    perf_instruction_pointer_after((hook_fargs1_t *)args, udata);
}

void perf_bp_event_before(hook_fargs2_t *args, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)args->arg1;
    struct rc_saved_pc saved;

    args->local.data0 = 0;
    args->local.data1 = 0;

    if (atomic_read(&active_mapping_count) == 0 || !regs || !user_mode(regs))
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_regs_pc_shared(rc_task_active_mm(current), regs, &saved);
    args->local.data0 = (unsigned long)saved.regs;
    args->local.data1 = saved.saved_pc;
    RC_HANDLER_EXIT();
}

void perf_bp_event_after(hook_fargs2_t *args, void *udata)
{
    perf_instruction_pointer_after((hook_fargs1_t *)args, udata);
}

void single_step_handler_before_rc(hook_fargs3_t *args, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    struct rc_saved_pc saved;

    args->local.data0 = 0;
    args->local.data1 = 0;

    if (atomic_read(&active_mapping_count) == 0 || !regs || !user_mode(regs))
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_regs_pc_shared(rc_task_active_mm(current), regs, &saved);
    args->local.data0 = (unsigned long)saved.regs;
    args->local.data1 = saved.saved_pc;
    RC_HANDLER_EXIT();
}

void single_step_handler_after_rc(hook_fargs3_t *args, void *udata)
{
    struct rc_saved_pc saved;

    saved.regs = (struct pt_regs *)args->local.data0;
    saved.saved_pc = args->local.data1;
    if (!saved.regs)
        return;

    RC_HANDLER_ENTER();
    rc_restore_sanitized_pc_shared(&saved);
    RC_HANDLER_EXIT();
}

void do_el0_softstep_before(hook_fargs2_t *args, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)args->arg1;
    struct rc_saved_pc saved;

    args->local.data0 = 0;
    args->local.data1 = 0;

    if (atomic_read(&active_mapping_count) == 0 || !regs || !user_mode(regs))
        return;

    RC_HANDLER_ENTER();
    rc_sanitize_regs_pc_shared(rc_task_active_mm(current), regs, &saved);
    args->local.data0 = (unsigned long)saved.regs;
    args->local.data1 = saved.saved_pc;
    RC_HANDLER_EXIT();
}

void do_el0_softstep_after(hook_fargs2_t *args, void *udata)
{
    perf_instruction_pointer_after((hook_fargs1_t *)args, udata);
}
