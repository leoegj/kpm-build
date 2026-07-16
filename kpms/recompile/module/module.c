/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/string.h>
#include <asm/current.h>
#include <syscall.h>

#include "../recompile_internal.h"
#include "symbol_table.h"

#ifndef __NR_prctl
#define __NR_prctl 167
#endif

#define RC_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static struct rc_step_hook rc_step_hook;
static bool rc_step_hook_registered;

static void rc_unregister_user_step_hook_manual(void)
{
    if (!rc_step_hook_registered)
        return;

    if (kptr_debug_hook_lock) {
        spin_lock(kptr_debug_hook_lock);
    } else {
        pr_warn("recompile: debug_hook_lock not found, falling back to unregister_user_step_hook\n");
        if (kfunc_unregister_user_step_hook)
            kfunc_unregister_user_step_hook(&rc_step_hook);
        rc_step_hook_registered = false;
        INIT_LIST_HEAD(&rc_step_hook.node);
        return;
    }

    list_del_rcu(&rc_step_hook.node);
    spin_unlock(kptr_debug_hook_lock);
    INIT_LIST_HEAD(&rc_step_hook.node);
    rc_step_hook_registered = false;
}

static int rc_user_step_hook_fn(struct pt_regs *regs, unsigned long esr)
{
    struct rc_saved_pc saved;

    (void)esr;

    if (!user_mode(regs))
        return DBG_HOOK_ERROR;

    saved.regs = NULL;
    saved.saved_pc = 0;

    if (atomic_read(&active_mapping_count) == 0)
        return DBG_HOOK_ERROR;

    rc_sanitize_regs_pc_shared(rc_task_active_mm(current), regs, &saved);
    if (!saved.regs)
        return DBG_HOOK_ERROR;

    if (kfunc_arm64_force_sig_fault)
        kfunc_arm64_force_sig_fault(SIGTRAP, TRAP_TRACE, regs->pc, "User debug trap");
    if (kfunc_user_rewind_single_step)
        kfunc_user_rewind_single_step(current);

    rc_restore_sanitized_pc_shared(&saved);
    return DBG_HOOK_HANDLED;
}

#define RESOLVE_FROM(var, candidates) \
    do { \
        var = (typeof(var))lookup_name_any((candidates), RC_ARRAY_SIZE(candidates)); \
    } while (0)

#define RESOLVE_FROM_REQUIRED(var, candidates, desc) \
    do { \
        var = (typeof(var))lookup_name_any((candidates), RC_ARRAY_SIZE(candidates)); \
        if (!var) { \
            pr_err("recompile: required symbol not found: %s\n", desc); \
            return -1; \
        } \
    } while (0)

int resolve_symbols(void)
{
    pr_info("recompile: resolving symbols...\n");

    RESOLVE_FROM_REQUIRED(rc_raw_spin_lock, rc_sym_raw_spin_lock, "_raw_spin_lock/__raw_spin_lock");
    RESOLVE_FROM_REQUIRED(rc_raw_spin_unlock, rc_sym_raw_spin_unlock, "_raw_spin_unlock/__raw_spin_unlock");

    RESOLVE_FROM_REQUIRED(kfunc_find_vma, rc_sym_find_vma, "find_vma");
    RESOLVE_FROM_REQUIRED(kfunc_get_task_mm, rc_sym_get_task_mm, "get_task_mm");
    RESOLVE_FROM_REQUIRED(kfunc_mmput, rc_sym_mmput, "mmput");

    RESOLVE_FROM(kfunc_kzalloc, rc_sym_kzalloc);
    RESOLVE_FROM_REQUIRED(kfunc_kfree, rc_sym_kfree, "kfree");
    if (!kfunc_kzalloc) {
        pr_err("recompile: required symbol not found: kzalloc/__kmalloc\n");
        return -1;
    }

    RESOLVE_FROM(kfunc___get_free_pages, rc_sym_get_free_pages);
    RESOLVE_FROM(kfunc_free_pages, rc_sym_free_pages);
    RESOLVE_FROM_REQUIRED(kfunc_copy_from_kernel_nofault,
                          rc_sym_copy_from_kernel_nofault,
                          "copy_from_kernel_nofault");

    if (rc_probe_page_table_config() < 0)
        return -1;
    if (rc_probe_physvirt_translation() < 0)
        return -1;

    RESOLVE_FROM(kfunc_flush_tlb_page, rc_sym_flush_tlb_page);
    RESOLVE_FROM(kfunc___flush_tlb_range, rc_sym_flush_tlb_range);
    RESOLVE_FROM(kfunc_flush_tlb_all, rc_sym_flush_tlb_all);
    RESOLVE_FROM(kfunc___ptep_modify_prot_start, rc_sym_ptep_modify_prot_start);
    RESOLVE_FROM(kfunc___ptep_modify_prot_commit, rc_sym_ptep_modify_prot_commit);
    RESOLVE_FROM(kfunc___split_huge_pmd, rc_sym_split_huge_pmd);

    RESOLVE_FROM_REQUIRED(kfunc_do_page_fault, rc_sym_do_page_fault, "do_page_fault");
    RESOLVE_FROM_REQUIRED(kfunc_exit_mmap, rc_sym_exit_mmap, "exit_mmap/__mmput");
    RESOLVE_FROM(kfunc_setup_sigframe, rc_sym_setup_sigframe);
    RESOLVE_FROM(kfunc_do_signal, rc_sym_do_signal);
    RESOLVE_FROM(kfunc_compat_setup_sigframe, rc_sym_compat_setup_sigframe);
    RESOLVE_FROM(kfunc_compat_setup_rt_frame, rc_sym_compat_setup_rt_frame);
    RESOLVE_FROM(kfunc_compat_setup_frame, rc_sym_compat_setup_frame);
    RESOLVE_FROM(kfunc_copy_regset_to_user, rc_sym_copy_regset_to_user);
    RESOLVE_FROM(kfunc_regset_get, rc_sym_regset_get);
    RESOLVE_FROM(kfunc_regset_get_alloc, rc_sym_regset_get_alloc);
    RESOLVE_FROM(kfunc_perf_bp_event, rc_sym_perf_bp_event);
    RESOLVE_FROM(kfunc_perf_instruction_pointer, rc_sym_perf_instruction_pointer);
    RESOLVE_FROM(kfunc_perf_reg_value, rc_sym_perf_reg_value);
    RESOLVE_FROM(kfunc_perf_callchain_user, rc_sym_perf_callchain_user);
    RESOLVE_FROM(kfunc_do_el0_softstep, rc_sym_do_el0_softstep);
    RESOLVE_FROM(kfunc_single_step_handler, rc_sym_single_step_handler);
    RESOLVE_FROM(kfunc_register_user_step_hook, rc_sym_register_user_step_hook);
    RESOLVE_FROM(kfunc_unregister_user_step_hook, rc_sym_unregister_user_step_hook);
    RESOLVE_FROM(kptr_debug_hook_lock, rc_sym_debug_hook_lock);
    RESOLVE_FROM(kfunc_user_rewind_single_step, rc_sym_user_rewind_single_step);
    RESOLVE_FROM(kfunc_arm64_force_sig_fault, rc_sym_arm64_force_sig_fault);

    RESOLVE_FROM_REQUIRED(rc_find_task_by_vpid, rc_sym_find_task_by_vpid, "find_task_by_vpid");
    RESOLVE_FROM(kfunc_rcu_read_lock, rc_sym_rcu_read_lock);
    RESOLVE_FROM(kfunc_rcu_read_unlock, rc_sym_rcu_read_unlock);

    RESOLVE_FROM(kfunc_dup_mmap, rc_sym_dup_mmap);
    RESOLVE_FROM(kfunc_copy_process, rc_sym_copy_process);

    pr_info("recompile: symbols resolved (flush_tlb_page=%px __flush_tlb_range=%px flush_tlb_all=%px ptep_start=%px ptep_commit=%px)\n",
            kfunc_flush_tlb_page, kfunc___flush_tlb_range, kfunc_flush_tlb_all,
            kfunc___ptep_modify_prot_start, kfunc___ptep_modify_prot_commit);
    pr_info("recompile: export hooks setup_sigframe=%px do_signal=%px compat_setup_sigframe=%px copy_regset_to_user=%px regset_get=%px regset_get_alloc=%px perf_bp_event=%px perf_ip=%px perf_reg_value=%px perf_callchain_user=%px softstep=%px single_step_handler=%px register_user_step_hook=%px\n",
            kfunc_setup_sigframe, kfunc_do_signal, kfunc_compat_setup_sigframe,
            kfunc_copy_regset_to_user, kfunc_regset_get, kfunc_regset_get_alloc,
            kfunc_perf_bp_event,
            kfunc_perf_instruction_pointer, kfunc_perf_reg_value,
            kfunc_perf_callchain_user, kfunc_do_el0_softstep,
            kfunc_single_step_handler, kfunc_register_user_step_hook);
    return 0;
}

int rc_validate_export_surfaces(void)
{
    /*
     * setup_sigframe is optional - on newer kernels (6.x+) it may be inlined.
     * We still protect PC leak via compat_setup_sigframe (for 32-bit),
     * copy_regset_to_user, and perf hooks.
     */
    if (!kfunc_copy_regset_to_user ||
        !kfunc_regset_get || !kfunc_regset_get_alloc ||
        !kfunc_perf_bp_event || !kfunc_perf_instruction_pointer ||
        !kfunc_perf_reg_value || !kfunc_perf_callchain_user) {
        pr_err("recompile: required export hook symbols incomplete\n");
        return -1;
    }
    if (!kfunc_setup_sigframe && !kfunc_do_signal)
        pr_warn("recompile: setup_sigframe and do_signal both not found, signal PC export unprotected\n");
    else if (!kfunc_setup_sigframe)
        pr_info("recompile: setup_sigframe not found, using do_signal as fallback\n");
    if ((kfunc_compat_setup_rt_frame || kfunc_compat_setup_frame) &&
        !kfunc_compat_setup_sigframe) {
        pr_err("recompile: compat signal present but compat_setup_sigframe missing\n");
        return -1;
    }
    if (!kfunc_do_el0_softstep && !kfunc_single_step_handler &&
        !(kfunc_register_user_step_hook &&
          kfunc_user_rewind_single_step && kfunc_arm64_force_sig_fault)) {
        pr_err("recompile: required single-step hook capability missing\n");
        return -1;
    }
    if (!kfunc_do_el0_softstep && !kfunc_single_step_handler &&
        kfunc_register_user_step_hook && !kptr_debug_hook_lock) {
        pr_err("recompile: register_user_step_hook available but debug_hook_lock missing\n");
        return -1;
    }
    if (!kfunc_dup_mmap && !kfunc_copy_process) {
        pr_err("recompile: required fork-guard capability missing: dup_mmap/copy_process\n");
        return -1;
    }
    return 0;
}

void wait_for_handlers_drain(const char *phase)
{
    int i, iters = 0;

    for (i = 0; i < 200000; i++)
        rc_cpu_relax();

    while (atomic_read(&rc_in_flight) > 0) {
        rc_cpu_relax();
        if (++iters > 10000000) {
            pr_warn("recompile: [%s] timeout waiting for handlers (in_flight=%d)\n",
                    phase, atomic_read(&rc_in_flight));
            break;
        }
    }
}

static long recompile_init(const char *args, const char *event, void *reserved)
{
    int ret;
    bool hooked_setup_sigframe = false;
    bool hooked_compat_setup_sigframe = false;
    bool hooked_copy_regset_to_user = false;
    bool hooked_regset_get = false;
    bool hooked_regset_get_alloc = false;
    bool hooked_perf_bp_event = false;
    bool hooked_perf_instruction_pointer = false;
    bool hooked_perf_reg_value = false;
    bool hooked_perf_callchain_user = false;
    bool hooked_do_el0_softstep = false;
    bool hooked_single_step_handler = false;

    pr_info("recompile: initializing...\n");

    ret = resolve_symbols();
    if (ret < 0)
        return ret;
    ret = rc_validate_export_surfaces();
    if (ret < 0)
        return ret;
    ret = scan_vma_offsets();
    if (ret < 0)
        return ret;

    /* Optional: scan mm->context.id offset for ASID-based TLB operations */
    ret = scan_mm_context_id();
    if (ret < 0)
        pr_info("recompile: mm->context.id scan failed (non-fatal, using fallback TLB flush)\n");

    ret = hook_wrap3(kfunc_do_page_fault, do_page_fault_before, do_page_fault_after, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook do_page_fault: %d\n", ret);
        return -1;
    }
    ret = hook_syscalln(__NR_prctl, 5, prctl_before, NULL, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook prctl: %d\n", ret);
        hook_unwrap(kfunc_do_page_fault, do_page_fault_before, do_page_fault_after);
        return -1;
    }
    ret = hook_wrap1(kfunc_exit_mmap, exit_mmap_before, NULL, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook exit_mmap: %d\n", ret);
        unhook_syscalln(__NR_prctl, prctl_before, NULL);
        hook_unwrap(kfunc_do_page_fault, do_page_fault_before, do_page_fault_after);
        return -1;
    }

    if (kfunc_setup_sigframe) {
        ret = hook_wrap4(kfunc_setup_sigframe, setup_sigframe_before, setup_sigframe_after, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_err("recompile: failed to hook setup_sigframe: %d\n", ret);
            goto err_unhook_exit_mmap;
        }
        hooked_setup_sigframe = true;
    } else if (kfunc_do_signal) {
        /* Fallback: hook do_signal when setup_sigframe is inlined */
        ret = hook_wrap1(kfunc_do_signal, do_signal_before, do_signal_after, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_err("recompile: failed to hook do_signal: %d\n", ret);
            goto err_unhook_exit_mmap;
        }
        hooked_setup_sigframe = true;  /* reuse flag for cleanup */
    }

    if (kfunc_compat_setup_sigframe) {
        ret = hook_wrap3(kfunc_compat_setup_sigframe,
                         compat_setup_sigframe_before,
                         compat_setup_sigframe_after, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_err("recompile: failed to hook compat_setup_sigframe: %d\n", ret);
            goto err_unhook_exports;
        }
        hooked_compat_setup_sigframe = true;
    }

    ret = hook_wrap6(kfunc_copy_regset_to_user, copy_regset_to_user_before,
                     copy_regset_to_user_after, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook copy_regset_to_user: %d\n", ret);
        goto err_unhook_exports;
    }
    hooked_copy_regset_to_user = true;

    ret = hook_wrap4(kfunc_regset_get, regset_get_before, regset_get_after, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook regset_get: %d\n", ret);
        goto err_unhook_exports;
    }
    hooked_regset_get = true;

    ret = hook_wrap4(kfunc_regset_get_alloc, regset_get_alloc_before,
                     regset_get_alloc_after, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook regset_get_alloc: %d\n", ret);
        goto err_unhook_exports;
    }
    hooked_regset_get_alloc = true;

    ret = hook_wrap2(kfunc_perf_bp_event, perf_bp_event_before, perf_bp_event_after, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook perf_bp_event: %d\n", ret);
        goto err_unhook_exports;
    }
    hooked_perf_bp_event = true;

    ret = hook_wrap1(kfunc_perf_instruction_pointer, perf_instruction_pointer_before,
                     perf_instruction_pointer_after, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook perf_instruction_pointer: %d\n", ret);
        goto err_unhook_exports;
    }
    hooked_perf_instruction_pointer = true;

    ret = hook_wrap2(kfunc_perf_reg_value, perf_reg_value_before, perf_reg_value_after, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook perf_reg_value: %d\n", ret);
        goto err_unhook_exports;
    }
    hooked_perf_reg_value = true;

    ret = hook_wrap2(kfunc_perf_callchain_user, perf_callchain_user_before,
                     perf_callchain_user_after, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook perf_callchain_user: %d\n", ret);
        goto err_unhook_exports;
    }
    hooked_perf_callchain_user = true;

    if (kfunc_do_el0_softstep) {
        ret = hook_wrap2(kfunc_do_el0_softstep, do_el0_softstep_before,
                         do_el0_softstep_after, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_err("recompile: failed to hook do_el0_softstep: %d\n", ret);
            goto err_unhook_exports;
        }
        hooked_do_el0_softstep = true;
    }

    if (!kfunc_do_el0_softstep && kfunc_single_step_handler) {
        ret = hook_wrap3(kfunc_single_step_handler, single_step_handler_before_rc,
                         single_step_handler_after_rc, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_err("recompile: failed to hook single_step_handler: %d\n", ret);
            goto err_unhook_exports;
        }
        hooked_single_step_handler = true;
    }

    if (!kfunc_do_el0_softstep && !kfunc_single_step_handler &&
        kfunc_register_user_step_hook &&
        kfunc_user_rewind_single_step && kfunc_arm64_force_sig_fault) {
        INIT_LIST_HEAD(&rc_step_hook.node);
        rc_step_hook.fn = rc_user_step_hook_fn;
        kfunc_register_user_step_hook(&rc_step_hook);
        rc_step_hook_registered = true;
    }

    if (kfunc_dup_mmap) {
        ret = hook_wrap2(kfunc_dup_mmap, before_dup_mmap, after_dup_mmap, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_err("recompile: failed to hook dup_mmap: %d\n", ret);
            goto err_unhook_exports;
        }
    } else {
        ret = hook_wrap8(kfunc_copy_process, before_copy_process, after_copy_process, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_err("recompile: failed to hook copy_process: %d\n", ret);
            goto err_unhook_exports;
        }
    }

    pr_info("recompile: module loaded\n");
    return 0;

err_unhook_exports:
    if (rc_step_hook_registered) {
        rc_unregister_user_step_hook_manual();
        wait_for_handlers_drain("err-user_step_hook");
    }
    if (hooked_single_step_handler)
        hook_unwrap(kfunc_single_step_handler, single_step_handler_before_rc,
                    single_step_handler_after_rc);
    if (hooked_do_el0_softstep)
        hook_unwrap(kfunc_do_el0_softstep, do_el0_softstep_before, do_el0_softstep_after);
    if (hooked_perf_callchain_user)
        hook_unwrap(kfunc_perf_callchain_user, perf_callchain_user_before,
                    perf_callchain_user_after);
    if (hooked_perf_reg_value)
        hook_unwrap(kfunc_perf_reg_value, perf_reg_value_before, perf_reg_value_after);
    if (hooked_perf_instruction_pointer)
        hook_unwrap(kfunc_perf_instruction_pointer, perf_instruction_pointer_before,
                    perf_instruction_pointer_after);
    if (hooked_perf_bp_event)
        hook_unwrap(kfunc_perf_bp_event, perf_bp_event_before, perf_bp_event_after);
    if (hooked_regset_get_alloc)
        hook_unwrap(kfunc_regset_get_alloc, regset_get_alloc_before, regset_get_alloc_after);
    if (hooked_regset_get)
        hook_unwrap(kfunc_regset_get, regset_get_before, regset_get_after);
    if (hooked_copy_regset_to_user)
        hook_unwrap(kfunc_copy_regset_to_user, copy_regset_to_user_before,
                    copy_regset_to_user_after);
    if (hooked_compat_setup_sigframe)
        hook_unwrap(kfunc_compat_setup_sigframe,
                    compat_setup_sigframe_before,
                    compat_setup_sigframe_after);
    if (hooked_setup_sigframe) {
        if (kfunc_setup_sigframe)
            hook_unwrap(kfunc_setup_sigframe, setup_sigframe_before, setup_sigframe_after);
        else if (kfunc_do_signal)
            hook_unwrap(kfunc_do_signal, do_signal_before, do_signal_after);
    }
err_unhook_exit_mmap:
    hook_unwrap(kfunc_exit_mmap, exit_mmap_before, NULL);
    unhook_syscalln(__NR_prctl, prctl_before, NULL);
    hook_unwrap(kfunc_do_page_fault, do_page_fault_before, do_page_fault_after);
    return -1;
}

static long recompile_exit(void *reserved)
{
    int count;

    if (rc_step_hook_registered) {
        rc_unregister_user_step_hook_manual();
        wait_for_handlers_drain("phase0-user_step_hook");
    }

    unhook_syscalln(__NR_prctl, prctl_before, NULL);
    wait_for_handlers_drain("phase1-prctl");

    count = rc_teardown_mappings_for_mm(NULL, "module unload", false);

    hook_unwrap(kfunc_do_page_fault, do_page_fault_before, do_page_fault_after);
    wait_for_handlers_drain("phase3-fault");

    /*
     * In init, we hook dup_mmap if available, otherwise copy_process.
     * Mirror that logic here: only unhook what was actually hooked.
     */
    if (kfunc_dup_mmap) {
        hook_unwrap(kfunc_dup_mmap, before_dup_mmap, after_dup_mmap);
        wait_for_handlers_drain("phase3.5-dup_mmap");
    } else if (kfunc_copy_process) {
        hook_unwrap(kfunc_copy_process, before_copy_process, after_copy_process);
        wait_for_handlers_drain("phase3.5-copy_process");
    }

    if (kfunc_single_step_handler) {
        hook_unwrap(kfunc_single_step_handler, single_step_handler_before_rc,
                    single_step_handler_after_rc);
        wait_for_handlers_drain("phase4-single_step_handler");
    }
    if (kfunc_do_el0_softstep) {
        hook_unwrap(kfunc_do_el0_softstep, do_el0_softstep_before, do_el0_softstep_after);
        wait_for_handlers_drain("phase4-do_el0_softstep");
    }
    if (kfunc_perf_callchain_user) {
        hook_unwrap(kfunc_perf_callchain_user, perf_callchain_user_before,
                    perf_callchain_user_after);
        wait_for_handlers_drain("phase4-perf_callchain_user");
    }
    if (kfunc_perf_reg_value) {
        hook_unwrap(kfunc_perf_reg_value, perf_reg_value_before, perf_reg_value_after);
        wait_for_handlers_drain("phase4-perf_reg_value");
    }
    if (kfunc_perf_instruction_pointer) {
        hook_unwrap(kfunc_perf_instruction_pointer, perf_instruction_pointer_before,
                    perf_instruction_pointer_after);
        wait_for_handlers_drain("phase4-perf_instruction_pointer");
    }
    if (kfunc_regset_get_alloc) {
        hook_unwrap(kfunc_regset_get_alloc, regset_get_alloc_before, regset_get_alloc_after);
        wait_for_handlers_drain("phase4-regset_get_alloc");
    }
    if (kfunc_perf_bp_event) {
        hook_unwrap(kfunc_perf_bp_event, perf_bp_event_before, perf_bp_event_after);
        wait_for_handlers_drain("phase4-perf_bp_event");
    }
    if (kfunc_regset_get) {
        hook_unwrap(kfunc_regset_get, regset_get_before, regset_get_after);
        wait_for_handlers_drain("phase4-regset_get");
    }
    if (kfunc_copy_regset_to_user) {
        hook_unwrap(kfunc_copy_regset_to_user, copy_regset_to_user_before,
                    copy_regset_to_user_after);
        wait_for_handlers_drain("phase4-copy_regset_to_user");
    }
    if (kfunc_compat_setup_sigframe) {
        hook_unwrap(kfunc_compat_setup_sigframe, compat_setup_sigframe_before,
                    compat_setup_sigframe_after);
        wait_for_handlers_drain("phase4-compat_setup_sigframe");
    }
    if (kfunc_setup_sigframe) {
        hook_unwrap(kfunc_setup_sigframe, setup_sigframe_before, setup_sigframe_after);
        wait_for_handlers_drain("phase4-setup_sigframe");
    } else if (kfunc_do_signal) {
        hook_unwrap(kfunc_do_signal, do_signal_before, do_signal_after);
        wait_for_handlers_drain("phase4-do_signal");
    }
    if (kfunc_exit_mmap) {
        hook_unwrap(kfunc_exit_mmap, exit_mmap_before, NULL);
        wait_for_handlers_drain("phase5-exit_mmap");
    }

    pr_info("recompile: unloaded (cleaned %d mappings)\n", count);
    return 0;
}

KPM_INIT(recompile_init);
KPM_EXIT(recompile_exit);
