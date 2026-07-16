/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_RECOMPILE_SYMBOL_TABLE_H_
#define _KPM_RECOMPILE_SYMBOL_TABLE_H_

/*
 * Keep symbol-name variants in one place so future kernel-version support is
 * usually just "append another candidate here".
 *
 * Only group together names with compatible signatures/semantics.
 *
 * Categories:
 *   1. Core capability symbols
 *   2. PC leak guard symbols
 *   3. Fork guard symbols
 *   4. Common helper symbols
 */

/* ========== Core Capability ========== */
static const char *const rc_sym_raw_spin_lock[] = {
    "_raw_spin_lock",
    "__raw_spin_lock",
};

static const char *const rc_sym_raw_spin_unlock[] = {
    "_raw_spin_unlock",
    "__raw_spin_unlock",
};

static const char *const rc_sym_find_vma[] = { "__find_vma", "find_vma" };
static const char *const rc_sym_get_task_mm[] = { "get_task_mm" };
static const char *const rc_sym_mmput[] = { "mmput" };
static const char *const rc_sym_kzalloc[] = { "kzalloc", "__kmalloc" };
static const char *const rc_sym_kfree[] = { "kfree" };
static const char *const rc_sym_get_free_pages[] = { "__get_free_pages", "get_free_pages_noprof" };
static const char *const rc_sym_free_pages[] = { "free_pages" };
static const char *const rc_sym_copy_from_kernel_nofault[] = { "copy_from_kernel_nofault" };
/* Used by dynamic physvirt probe path */
static const char *const rc_sym_memstart_addr[] = { "memstart_addr" };
/* Used by dynamic physvirt probe path */
static const char *const rc_sym_physvirt_offset[] = { "physvirt_offset" };
static const char *const rc_sym_flush_tlb_page[] = { "flush_tlb_page" };
static const char *const rc_sym_flush_tlb_range[] = { "__flush_tlb_range" };
static const char *const rc_sym_flush_tlb_all[] = { "flush_tlb_all" };
static const char *const rc_sym_ptep_modify_prot_start[] = { "__ptep_modify_prot_start" };
static const char *const rc_sym_ptep_modify_prot_commit[] = { "__ptep_modify_prot_commit" };
static const char *const rc_sym_split_huge_pmd[] = { "__split_huge_pmd" };

/* ========== PC Leak Guard ========== */
static const char *const rc_sym_do_page_fault[] = { "do_page_fault" };
static const char *const rc_sym_exit_mmap[] = { "exit_mmap", "__mmput" };
static const char *const rc_sym_setup_sigframe[] = { "setup_sigframe" };
static const char *const rc_sym_do_signal[] = { "do_signal" };
static const char *const rc_sym_compat_setup_sigframe[] = { "compat_setup_sigframe" };
static const char *const rc_sym_compat_setup_rt_frame[] = { "compat_setup_rt_frame" };
static const char *const rc_sym_compat_setup_frame[] = { "compat_setup_frame" };
static const char *const rc_sym_copy_regset_to_user[] = { "copy_regset_to_user" };
static const char *const rc_sym_regset_get[] = { "regset_get" };
static const char *const rc_sym_regset_get_alloc[] = { "regset_get_alloc" };
static const char *const rc_sym_perf_bp_event[] = { "perf_bp_event" };
static const char *const rc_sym_perf_instruction_pointer[] = { "perf_instruction_pointer" };
static const char *const rc_sym_perf_reg_value[] = { "perf_reg_value" };
static const char *const rc_sym_perf_callchain_user[] = { "perf_callchain_user" };
static const char *const rc_sym_do_el0_softstep[] = { "do_el0_softstep" };
static const char *const rc_sym_single_step_handler[] = { "single_step_handler" };
static const char *const rc_sym_register_user_step_hook[] = { "register_user_step_hook" };
static const char *const rc_sym_unregister_user_step_hook[] = { "unregister_user_step_hook" };
static const char *const rc_sym_debug_hook_lock[] = { "debug_hook_lock" };
static const char *const rc_sym_user_rewind_single_step[] = { "user_rewind_single_step" };
static const char *const rc_sym_arm64_force_sig_fault[] = { "arm64_force_sig_fault" };

/* ========== Common Helpers ========== */
static const char *const rc_sym_find_task_by_vpid[] = { "find_task_by_vpid" };
static const char *const rc_sym_rcu_read_lock[] = { "__rcu_read_lock" };
static const char *const rc_sym_rcu_read_unlock[] = { "__rcu_read_unlock" };

/* ========== Fork Guard ========== */
static const char *const rc_sym_dup_mmap[] = { "dup_mmap" };
static const char *const rc_sym_copy_process[] = { "copy_process" };

#endif
