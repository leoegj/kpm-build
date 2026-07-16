/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_RECOMPILE_INTERNAL_H_
#define _KPM_RECOMPILE_INTERNAL_H_

#include <hook.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <asm/ptrace.h>
#include <asm/atomic.h>
#include <linux/elf.h>

#include "recompile.h"

extern void (*rc_raw_spin_lock)(raw_spinlock_t *lock);
extern void (*rc_raw_spin_unlock)(raw_spinlock_t *lock);
extern long (*kfunc_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);

#undef spin_lock
#undef spin_unlock
#undef raw_spin_lock
#undef raw_spin_unlock
#define raw_spin_lock(lock) rc_raw_spin_lock(lock)
#define raw_spin_unlock(lock) rc_raw_spin_unlock(lock)
#define spin_lock(lock) raw_spin_lock(&(lock)->rlock)
#define spin_unlock(lock) raw_spin_unlock(&(lock)->rlock)

extern struct list_head mapping_list;
extern spinlock_t global_lock;
extern atomic_t rc_in_flight;
extern atomic_t active_mapping_count;
extern atomic_t stat_fork_pause;
extern atomic_t stat_fork_resume;
extern atomic_t stat_fork_skipped;
extern atomic_t stat_fault_redirect;

extern void *(*kfunc_find_vma)(void *mm, unsigned long addr);
extern void *(*kfunc_get_task_mm)(void *task);
extern void (*kfunc_mmput)(void *mm);
extern void *(*kfunc_kzalloc)(size_t size, unsigned int flags);
extern void (*kfunc_kfree)(void *ptr);
extern unsigned long (*kfunc___get_free_pages)(unsigned int gfp_mask, unsigned int order);
extern void (*kfunc_free_pages)(unsigned long addr, unsigned int order);
extern void (*kfunc_flush_tlb_page)(void *vma, unsigned long uaddr);
extern void (*kfunc___flush_tlb_range)(void *vma, unsigned long start, unsigned long end,
                                       unsigned long stride, bool last_level, int tlb_level);
extern void (*kfunc_flush_tlb_all)(void);
struct rc_pte;
extern struct rc_pte (*kfunc___ptep_modify_prot_start)(void *vma, unsigned long addr,
                                                       struct rc_pte *ptep);
extern void (*kfunc___ptep_modify_prot_commit)(void *vma, unsigned long addr,
                                               struct rc_pte *ptep, struct rc_pte pte);
extern void (*kfunc___split_huge_pmd)(void *vma, void *pmd, unsigned long address,
                                      bool freeze, void *page);
extern void (*kfunc_rcu_read_lock)(void);
extern void (*kfunc_rcu_read_unlock)(void);
extern struct task_struct *(*rc_find_task_by_vpid)(pid_t nr);

extern void *kfunc_do_page_fault;
extern void *kfunc_setup_sigframe;
extern void *kfunc_do_signal;
extern void *kfunc_compat_setup_sigframe;
extern void *kfunc_compat_setup_rt_frame;
extern void *kfunc_compat_setup_frame;
extern void *kfunc_copy_regset_to_user;
extern void *kfunc_regset_get;
extern void *kfunc_regset_get_alloc;
extern void *kfunc_perf_bp_event;
extern void *kfunc_perf_instruction_pointer;
extern void *kfunc_perf_reg_value;
extern void *kfunc_perf_callchain_user;
extern void *kfunc_do_el0_softstep;
extern void *kfunc_single_step_handler;
extern void *kfunc_exit_mmap;
extern void *kfunc_dup_mmap;
extern void *kfunc_copy_process;
extern void (*kfunc_register_user_step_hook)(void *hook);
extern void (*kfunc_unregister_user_step_hook)(void *hook);
extern spinlock_t *kptr_debug_hook_lock;
extern void (*kfunc_user_rewind_single_step)(void *task);
extern void (*kfunc_arm64_force_sig_fault)(int signo, int code, unsigned long far, const char *str);

extern s64 *kvar_memstart_addr;
extern s64 *kvar_physvirt_offset;
extern unsigned long page_offset_base;
extern s64 detected_physvirt_offset;
extern int physvirt_offset_valid;
extern int rc_page_shift;
extern int rc_page_level;
extern int16_t vma_vm_mm_offset;
extern int16_t mm_context_id_offset;

#define RC_HANDLER_ENTER() atomic_inc(&rc_in_flight)
#define RC_HANDLER_EXIT()  atomic_dec(&rc_in_flight)

struct rc_saved_pc {
    struct pt_regs *regs;
    unsigned long saved_pc;
};

struct rc_pte {
    u64 pte;
};

struct rc_step_hook {
    struct list_head node;
    int (*fn)(struct pt_regs *regs, unsigned long esr);
};

#ifndef DBG_HOOK_HANDLED
#define DBG_HOOK_HANDLED 0
#endif
#ifndef DBG_HOOK_ERROR
#define DBG_HOOK_ERROR 1
#endif
#ifndef TRAP_TRACE
#define TRAP_TRACE 2
#endif
#ifndef SIGTRAP
#define SIGTRAP 5
#endif

#define VMA_VM_START_OFFSET     0x00
#define VMA_VM_END_OFFSET       0x08
#define GET_FIELD(ptr, offset, type) (*(type *)((char *)(ptr) + (offset)))

/*
 * Minimal regset descriptors matching include/linux/regset.h.
 * We only need the core-note discriminator to identify PRSTATUS exports.
 */
struct rc_user_regset {
    void *regset_get;
    void *set;
    void *active;
    void *writeback;
    unsigned int n;
    unsigned int size;
    unsigned int align;
    unsigned int bias;
    unsigned int core_note_type;
    const char *core_note_name;
};

struct rc_user_regset_view {
    const char *name;
    const struct rc_user_regset *regsets;
    unsigned int n;
    u32 e_flags;
    u16 e_machine;
    u8 ei_osabi;
};

#define RC_COMPAT_PERF_PC_REG 15
#define RC_PERF_REG_ARM64_PC  32

#ifndef CLONE_VM
#define CLONE_VM 0x00000100
#endif

static inline void *rc_task_active_mm(struct task_struct *task)
{
    if (task_struct_offset.active_mm_offset < 0)
        return NULL;
    return *(void **)((char *)task + task_struct_offset.active_mm_offset);
}

static inline unsigned long vma_start(void *vma)
{
    return GET_FIELD(vma, VMA_VM_START_OFFSET, unsigned long);
}

static inline void *vma_mm(void *vma)
{
    if (vma_vm_mm_offset < 0)
        return NULL;
    return GET_FIELD(vma, vma_vm_mm_offset, void *);
}

static inline void rc_cpu_relax(void)
{
    asm volatile("yield" ::: "memory");
}

static inline bool rc_is_kva(unsigned long addr)
{
    return (addr >> 48) == 0xffff;
}

static inline bool rc_safe_read_u64(unsigned long addr, u64 *out)
{
    if (!rc_is_kva(addr))
        return false;
    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(out, (const void *)addr, sizeof(*out)) != 0)
            return false;
    } else {
        *out = *(u64 *)addr;
    }
    return true;
}

#define ESR_ELx_EC_SHIFT        26
#define ESR_ELx_EC_MASK         (0x3FUL << ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC(esr)         (((esr) & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC_IABT_LOW     0x20

static inline bool is_el0_instruction_abort(unsigned int esr)
{
    return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW;
}

static inline bool is_permission_fault(unsigned int esr)
{
    unsigned int fsc = esr & 0x3F;
    return (fsc & 0x3C) == 0x0C;
}

static inline bool is_translation_fault(unsigned int esr)
{
    unsigned int fsc = esr & 0x3F;
    return (fsc & 0x3C) == 0x04;
}

unsigned long lookup_name_safe(const char *name);
unsigned long lookup_name_any(const char *const *names, size_t count);
int rc_probe_page_table_config(void);
int rc_probe_physvirt_translation(void);
int resolve_symbols(void);
int rc_validate_export_surfaces(void);
int scan_vma_offsets(void);
int scan_mm_context_id(void);
void wait_for_handlers_drain(const char *phase);

unsigned long mm_get_asid(void *mm);
u64 *rc_get_user_pte(void *mm, unsigned long addr);
void rc_set_pte(u64 *ptep, u64 new_pte);
int rc_write_user_pte(void *mm, void *vma, unsigned long addr, u64 *ptep,
                      u64 new_pte, bool flush_tlb);
int rc_try_strip_exec(void *mm, void *vma, unsigned long page_addr, u64 *orig_pte, unsigned long *pfn);
int rc_try_split_pmd(void *mm, void *vma, unsigned long addr);
int rc_restore_pte(void *mm, void *vma, unsigned long addr, u64 orig_pte);
struct recompile_mapping *rc_find_mapping(void *mm, unsigned long addr);
void rc_mapping_put(struct recompile_mapping *m);
int rc_do_register(void *mm, unsigned long orig_addr, unsigned long recomp_addr);
int rc_do_release(void *mm, unsigned long orig_addr);
int rc_teardown_mappings_for_mm(void *mm, const char *reason, bool skip_pte_restore);

void do_page_fault_before(hook_fargs3_t *args, void *udata);
void do_page_fault_after(hook_fargs3_t *args, void *udata);
void exit_mmap_before(hook_fargs1_t *args, void *udata);
void before_dup_mmap(hook_fargs2_t *args, void *udata);
void after_dup_mmap(hook_fargs2_t *args, void *udata);
void before_copy_process(hook_fargs8_t *args, void *udata);
void after_copy_process(hook_fargs8_t *args, void *udata);
void prctl_before(hook_fargs4_t *args, void *udata);

void setup_sigframe_before(hook_fargs4_t *args, void *udata);
void setup_sigframe_after(hook_fargs4_t *args, void *udata);
void do_signal_before(hook_fargs1_t *args, void *udata);
void do_signal_after(hook_fargs1_t *args, void *udata);
void compat_setup_sigframe_before(hook_fargs3_t *args, void *udata);
void compat_setup_sigframe_after(hook_fargs3_t *args, void *udata);
void rc_sanitize_regs_pc_shared(void *mm, struct pt_regs *regs, struct rc_saved_pc *saved);
void rc_restore_sanitized_pc_shared(struct rc_saved_pc *saved);
void copy_regset_to_user_before(hook_fargs6_t *args, void *udata);
void copy_regset_to_user_after(hook_fargs6_t *args, void *udata);
void regset_get_before(hook_fargs4_t *args, void *udata);
void regset_get_after(hook_fargs4_t *args, void *udata);
void regset_get_alloc_before(hook_fargs4_t *args, void *udata);
void regset_get_alloc_after(hook_fargs4_t *args, void *udata);
void perf_instruction_pointer_before(hook_fargs1_t *args, void *udata);
void perf_instruction_pointer_after(hook_fargs1_t *args, void *udata);
void perf_reg_value_before(hook_fargs2_t *args, void *udata);
void perf_reg_value_after(hook_fargs2_t *args, void *udata);
void perf_callchain_user_before(hook_fargs2_t *args, void *udata);
void perf_callchain_user_after(hook_fargs2_t *args, void *udata);
void perf_bp_event_before(hook_fargs2_t *args, void *udata);
void perf_bp_event_after(hook_fargs2_t *args, void *udata);
void single_step_handler_before_rc(hook_fargs3_t *args, void *udata);
void single_step_handler_after_rc(hook_fargs3_t *args, void *udata);
void do_el0_softstep_before(hook_fargs2_t *args, void *udata);
void do_el0_softstep_after(hook_fargs2_t *args, void *udata);

#endif
