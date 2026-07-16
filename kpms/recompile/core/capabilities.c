/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Recompile Redirect KPM Module
 *
 * Removes execute permission from original code pages and redirects
 * execution to user-space recompiled pages by modifying PC on
 * instruction abort fault.
 *
 * Flow:
 *   1. User registers (pid, orig_page, recomp_page) via prctl
 *   2. Kernel strips X permission from orig_page PTE (set PTE_UXN)
 *   3. When process executes at orig_page+offset, instruction abort fires
 *   4. do_page_fault hook catches it, sets regs->pc = recomp_page+offset
 *   5. Execution continues transparently at the recompiled code
 *
 * Copyright (C) 2024
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <hook.h>
#include <ksyms.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <pgtable.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/ptrace.h>
#include <asm/atomic.h>
#include <linux/err.h>
#include <linux/elf.h>

#include "../recompile.h"
#include "../recompile_internal.h"

#ifndef __NR_prctl
#define __NR_prctl 167
#endif

KPM_NAME("recompile");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("recompile");
KPM_DESCRIPTION("Recompile Redirect - Execute recompiled code pages");

/* ========== ARM64 helpers ========== */

static inline void cpu_relax(void)
{
    asm volatile("yield" ::: "memory");
}

static inline bool is_kva(unsigned long addr)
{
    return (addr >> 48) == 0xffff;
}

/* ========== Safe memory read ========== */

long (*kfunc_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);

static inline bool safe_read_u64(unsigned long addr, u64 *out)
{
    if (!is_kva(addr))
        return false;
    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(out, (const void *)addr, sizeof(*out)) != 0)
            return false;
    } else {
        *out = *(u64 *)addr;
    }
    return true;
}

/* ========== Kernel function pointers ========== */

void (*rc_raw_spin_lock)(raw_spinlock_t *lock);
void (*rc_raw_spin_unlock)(raw_spinlock_t *lock);

void *(*kfunc_find_vma)(void *mm, unsigned long addr);
void *(*kfunc_get_task_mm)(void *task);
void (*kfunc_mmput)(void *mm);

s64 *kvar_memstart_addr;
s64 *kvar_physvirt_offset;
unsigned long page_offset_base;
s64 detected_physvirt_offset;
int physvirt_offset_valid = 0;

int rc_page_shift;
int rc_page_level;

void (*kfunc_flush_tlb_page)(void *vma, unsigned long uaddr);
void (*kfunc___flush_tlb_range)(void *vma, unsigned long start, unsigned long end,
                                unsigned long stride, bool last_level, int tlb_level);
void (*kfunc_flush_tlb_all)(void);
struct rc_pte (*kfunc___ptep_modify_prot_start)(void *vma, unsigned long addr,
                                                struct rc_pte *ptep);
void (*kfunc___ptep_modify_prot_commit)(void *vma, unsigned long addr,
                                        struct rc_pte *ptep, struct rc_pte pte);

void (*kfunc___split_huge_pmd)(void *vma, void *pmd, unsigned long address,
                               bool freeze, void *page);

void *(*kfunc_kzalloc)(size_t size, unsigned int flags);
void (*kfunc_kfree)(void *ptr);

unsigned long (*kfunc___get_free_pages)(unsigned int gfp_mask, unsigned int order);
void (*kfunc_free_pages)(unsigned long addr, unsigned int order);

void *kfunc_do_page_fault = NULL;
void *kfunc_setup_sigframe = NULL;
void *kfunc_do_signal = NULL;
void *kfunc_compat_setup_sigframe = NULL;
void *kfunc_compat_setup_rt_frame = NULL;
void *kfunc_compat_setup_frame = NULL;
void *kfunc_copy_regset_to_user = NULL;
void *kfunc_regset_get = NULL;
void *kfunc_regset_get_alloc = NULL;
void *kfunc_perf_bp_event = NULL;
void *kfunc_perf_instruction_pointer = NULL;
void *kfunc_perf_reg_value = NULL;
void *kfunc_perf_callchain_user = NULL;
void *kfunc_do_el0_softstep = NULL;
void *kfunc_single_step_handler = NULL;
void *kfunc_exit_mmap = NULL;
void *kfunc_dup_mmap = NULL;
void *kfunc_copy_process = NULL;
void (*kfunc_register_user_step_hook)(void *hook) = NULL;
void (*kfunc_unregister_user_step_hook)(void *hook) = NULL;
spinlock_t *kptr_debug_hook_lock = NULL;
void (*kfunc_user_rewind_single_step)(void *task) = NULL;
void (*kfunc_arm64_force_sig_fault)(int signo, int code, unsigned long far, const char *str) = NULL;

struct task_struct *(*rc_find_task_by_vpid)(pid_t nr);
void (*kfunc_rcu_read_lock)(void);
void (*kfunc_rcu_read_unlock)(void);

/* ========== VMA/mm helpers ========== */

int16_t vma_vm_mm_offset = -1;
int16_t mm_context_id_offset = -1;

static inline unsigned long vma_end(void *vma)
{
    return GET_FIELD(vma, VMA_VM_END_OFFSET, unsigned long);
}

static inline void *mm_pgd(void *mm)
{
    if (mm_struct_offset.pgd_offset < 0)
        return NULL;
    return GET_FIELD(mm, mm_struct_offset.pgd_offset, void *);
}

/* ========== Address translation ========== */

static inline unsigned long phys_to_virt_safe(unsigned long pa)
{
    if (physvirt_offset_valid)
        return pa + detected_physvirt_offset;
    else if (kvar_physvirt_offset)
        return pa + *kvar_physvirt_offset;
    else
        return (pa - *kvar_memstart_addr) + page_offset_base;
}

static inline unsigned long kaddr_to_phys(unsigned long vaddr)
{
    if (physvirt_offset_valid)
        return vaddr - detected_physvirt_offset;
    else if (kvar_physvirt_offset)
        return vaddr - *kvar_physvirt_offset;
    else
        return (vaddr - page_offset_base) + *kvar_memstart_addr;
}

/* ========== Global state ========== */

LIST_HEAD(mapping_list);
DEFINE_SPINLOCK(global_lock);
atomic_t rc_in_flight = ATOMIC_INIT(0);
atomic_t active_mapping_count = ATOMIC_INIT(0);

atomic_t stat_fork_pause   = ATOMIC_INIT(0);
atomic_t stat_fork_resume  = ATOMIC_INIT(0);
atomic_t stat_fork_skipped = ATOMIC_INIT(0);
atomic_t stat_fault_redirect = ATOMIC_INIT(0);

/* ========== ESR parsing ========== */

/* ========== Page table operations ========== */

static inline unsigned long pte_index(unsigned long addr)
{
    return (addr >> PAGE_SHIFT) & (512 - 1);
}

static inline unsigned long pgd_index(unsigned long addr)
{
    int pxd_bits = rc_page_shift - 3;
    int pgdir_shift = rc_page_shift + (rc_page_level - 1) * pxd_bits;
    return (addr >> pgdir_shift) & ((1UL << pxd_bits) - 1);
}

static inline unsigned long pud_index(unsigned long addr)
{
    int pxd_bits = rc_page_shift - 3;
    int pud_shift = rc_page_shift + (rc_page_level - 2) * pxd_bits;
    return (addr >> pud_shift) & ((1UL << pxd_bits) - 1);
}

static inline unsigned long pmd_index(unsigned long addr)
{
    int pxd_bits = rc_page_shift - 3;
    int pmd_shift = rc_page_shift + 1 * pxd_bits;
    return (addr >> pmd_shift) & ((1UL << pxd_bits) - 1);
}

#define PXD_TYPE_MASK   0x3UL
#define PXD_TYPE_SECT   0x1UL
#define PXD_TYPE_TABLE  0x3UL

static inline bool pmd_sect(u64 pmd) { return (pmd & PXD_TYPE_MASK) == PXD_TYPE_SECT; }
static inline bool pmd_table(u64 pmd) { return (pmd & PXD_TYPE_MASK) == PXD_TYPE_TABLE; }

static inline unsigned long pxd_page_vaddr(u64 pxd_val)
{
    unsigned long pa = pxd_val & 0x0000FFFFFFFFF000UL;
    return phys_to_virt_safe(pa);
}

static void *rc_pgd_offset(void *mm, unsigned long addr)
{
    void *pgd = mm_pgd(mm);
    if (!pgd)
        return NULL;
    return (void *)((u64 *)pgd + pgd_index(addr));
}

static void *rc_pud_offset(void *p4d, unsigned long addr)
{
    u64 p4d_val;
    unsigned long pud_base;

    if (!p4d || !is_kva((unsigned long)p4d))
        return NULL;
    if (!safe_read_u64((unsigned long)p4d, &p4d_val))
        return NULL;
    if (!p4d_val)
        return NULL;
    pud_base = pxd_page_vaddr(p4d_val);
    if (!is_kva(pud_base))
        return NULL;
    return (void *)((u64 *)pud_base + pud_index(addr));
}

static void *rc_pmd_offset(void *pud, unsigned long addr)
{
    u64 pud_val;
    unsigned long pmd_base;

    if (!pud || !is_kva((unsigned long)pud))
        return NULL;
    if (!safe_read_u64((unsigned long)pud, &pud_val))
        return NULL;
    if (!pud_val)
        return NULL;
    pmd_base = pxd_page_vaddr(pud_val);
    if (!is_kva(pmd_base))
        return NULL;
    return (void *)((u64 *)pmd_base + pmd_index(addr));
}

static u64 *rc_pte_offset(void *pmd, unsigned long addr)
{
    u64 pmd_val;
    unsigned long pte_table;

    if (!pmd || !is_kva((unsigned long)pmd))
        return NULL;
    if (!safe_read_u64((unsigned long)pmd, &pmd_val))
        return NULL;
    pte_table = pxd_page_vaddr(pmd_val);
    if (!is_kva(pte_table))
        return NULL;
    return (u64 *)(pte_table + pte_index(addr) * sizeof(u64));
}

int rc_try_split_pmd(void *mm, void *vma, unsigned long addr)
{
    void *pgd, *pud, *pmd;
    u64 pgd_val, pud_val, pmd_val;

    pgd = rc_pgd_offset(mm, addr);
    if (!pgd || !is_kva((unsigned long)pgd))
        return 0;
    if (!safe_read_u64((unsigned long)pgd, &pgd_val) || pgd_val == 0)
        return 0;

    if (rc_page_level == 4) {
        pud = rc_pud_offset(pgd, addr);
        if (!pud)
            return 0;
        if (!safe_read_u64((unsigned long)pud, &pud_val) || pud_val == 0)
            return 0;
        pmd = rc_pmd_offset(pud, addr);
    } else {
        pmd = rc_pmd_offset(pgd, addr);
    }
    if (!pmd)
        return 0;
    if (!safe_read_u64((unsigned long)pmd, &pmd_val) || pmd_val == 0)
        return 0;

    if (!pmd_sect(pmd_val))
        return 0;

    if (!kfunc___split_huge_pmd) {
        pr_err("recompile: addr %lx is PMD block but __split_huge_pmd not available\n", addr);
        return -38;
    }

    if (!vma) {
        pr_err("recompile: addr %lx is PMD block but vma is NULL (cannot split)\n", addr);
        return -38;
    }

    {
        int pxd_bits = rc_page_shift - 3;
        unsigned long pmd_shift_val = rc_page_shift + 1 * pxd_bits;
        unsigned long block_mask = ~((1UL << pmd_shift_val) - 1);
        kfunc___split_huge_pmd(vma, pmd, addr & block_mask, false, NULL);
    }

    if (!safe_read_u64((unsigned long)pmd, &pmd_val))
        return -14;
    if (pmd_sect(pmd_val))
        return -1;
    return 0;
}

u64 *rc_get_user_pte(void *mm, unsigned long addr)
{
    void *pgd, *pud, *pmd;
    u64 pgd_val, pud_val, pmd_val;

    pgd = rc_pgd_offset(mm, addr);
    if (!pgd || !is_kva((unsigned long)pgd))
        return NULL;
    if (!safe_read_u64((unsigned long)pgd, &pgd_val) || pgd_val == 0)
        return NULL;

    if (rc_page_level == 4) {
        pud = rc_pud_offset(pgd, addr);
        if (!pud)
            return NULL;
        if (!safe_read_u64((unsigned long)pud, &pud_val) || pud_val == 0)
            return NULL;
        pmd = rc_pmd_offset(pud, addr);
    } else {
        pmd = rc_pmd_offset(pgd, addr);
    }
    if (!pmd)
        return NULL;
    if (!safe_read_u64((unsigned long)pmd, &pmd_val) || pmd_val == 0)
        return NULL;
    if (pmd_sect(pmd_val) || !pmd_table(pmd_val))
        return NULL;
    return rc_pte_offset(pmd, addr);
}

/* ========== TLB flush ========== */

u64 mm_get_asid(void *mm)
{
    u64 context_id;

    if (!mm || mm_context_id_offset < 0)
        return 0;
    context_id = *(u64 *)((char *)mm + mm_context_id_offset);
    return context_id & 0xFFFF;
}

static void rc_flush_tlb_page(void *mm, unsigned long uaddr)
{
    /*
     * Never call kernel flush_tlb_page / __flush_tlb_range - they require
     * a valid vma pointer (deref vma->vm_mm for ASID) which we don't have.
     * Use TLBI VALE1IS with the mm's ASID directly instead.
     */
    u64 asid = mm_get_asid(mm);

    if (asid) {
        u64 operand = (asid << 48) | ((uaddr >> 12) & 0xFFFFFFFFFUL);
        asm volatile("tlbi vale1is, %0" : : "r"(operand) : "memory");
    } else {
        asm volatile("tlbi vmalle1is" : : : "memory");
    }
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static bool rc_supported_raw_pte(u64 pte_val)
{
    if (!(pte_val & PTE_VALID))
        return false;
    if ((pte_val & PTE_TYPE_PAGE) != PTE_TYPE_PAGE) {
        pr_err("recompile: unsupported non-leaf/non-page PTE format: 0x%llx\n",
               (unsigned long long)pte_val);
        return false;
    }
    if (pte_valid_cont(pte_val)) {
        pr_err("recompile: unsupported contiguous PTE format: 0x%llx\n",
               (unsigned long long)pte_val);
        return false;
    }
    return true;
}

/* ========== PTE manipulation ========== */

void rc_set_pte(u64 *ptep, u64 pte)
{
    *(volatile u64 *)ptep = pte;
}

int rc_write_user_pte(void *mm, void *vma, unsigned long addr, u64 *ptep,
                      u64 new_pte, bool flush_tlb)
{
    if (vma && kfunc___ptep_modify_prot_start && kfunc___ptep_modify_prot_commit) {
        struct rc_pte old_pte;
        struct rc_pte new_pte_wrapped = { .pte = new_pte };

        old_pte = kfunc___ptep_modify_prot_start(vma, addr, (struct rc_pte *)ptep);
        if (!rc_supported_raw_pte(old_pte.pte))
            return -95;
        kfunc___ptep_modify_prot_commit(vma, addr, (struct rc_pte *)ptep, new_pte_wrapped);
    } else {
        rc_set_pte(ptep, new_pte);
    }

    if (flush_tlb)
        rc_flush_tlb_page(mm, addr);
    return 0;
}

int rc_try_strip_exec(void *mm, void *vma, unsigned long addr,
                      u64 *out_orig_pte, unsigned long *out_pfn)
{
    u64 *ptep;
    u64 pte_val, new_pte;

    ptep = rc_get_user_pte(mm, addr);
    if (!ptep)
        return 1;

    pte_val = *(volatile u64 *)ptep;
    /* PTE value 0 means page not yet mapped - defer to fault handler */
    if (pte_val == 0 || !(pte_val & PTE_VALID))
        return 1;
    if (!rc_supported_raw_pte(pte_val))
        return -95;

    *out_orig_pte = pte_val;
    *out_pfn = (pte_val & 0x0000FFFFFFFFF000UL) >> PAGE_SHIFT;

    new_pte = pte_val | PTE_UXN;
    return rc_write_user_pte(mm, vma, addr, ptep, new_pte, true);
}

int rc_restore_pte(void *mm, void *vma, unsigned long addr, u64 orig_pte)
{
    u64 *ptep;

    ptep = rc_get_user_pte(mm, addr);
    if (!ptep)
        return -1;

    return rc_write_user_pte(mm, vma, addr, ptep, orig_pte, true);
}

/* ========== Mapping management ========== */

struct recompile_mapping *rc_find_mapping(void *mm, unsigned long addr)
{
    struct list_head *pos;
    unsigned long page_addr = addr & PAGE_MASK;

    if (list_empty(&mapping_list))
        return NULL;

    spin_lock(&global_lock);
    list_for_each(pos, &mapping_list) {
        struct recompile_mapping *m = container_of(pos, struct recompile_mapping, list);
        if (m->mm == mm && m->orig_page == page_addr && !m->dead) {
            atomic_inc(&m->refcount);
            spin_unlock(&global_lock);
            return m;
        }
    }
    spin_unlock(&global_lock);
    return NULL;
}

void rc_mapping_put(struct recompile_mapping *m)
{
    if (atomic_dec_return(&m->refcount) <= 0 && m->dead)
        kfunc_kfree(m);
}

int rc_do_register(void *mm, unsigned long orig_addr, unsigned long recomp_addr)
{
    unsigned long orig_page = orig_addr & PAGE_MASK;
    unsigned long recomp_page = recomp_addr & PAGE_MASK;
    struct recompile_mapping *m;
    u64 orig_pte = 0;
    unsigned long pfn = 0;
    int ret;

    m = rc_find_mapping(mm, orig_page);
    if (m) {
        pr_err("recompile: mapping already exists for page %lx\n", orig_page);
        rc_mapping_put(m);
        return -17;
    }

    /*
     * Skip find_vma() which requires mmap_lock - we don't have easy access
     * to it from prctl context. Instead, try PMD split and PTE operations
     * directly; they will fail gracefully if the address is invalid.
     * Pass NULL vma to these functions.
     */
    ret = rc_try_split_pmd(mm, NULL, orig_page);
    if (ret < 0) {
        pr_err("recompile: PMD split failed for %lx: %d\n", orig_page, ret);
        return ret;
    }

    ret = rc_try_strip_exec(mm, NULL, orig_page, &orig_pte, &pfn);
    if (ret < 0) {
        pr_err("recompile: failed to strip X for %lx\n", orig_page);
        return ret;
    }

    m = kfunc_kzalloc(sizeof(*m), 0x14000C0);
    if (!m) {
        if (ret == 0)
            rc_restore_pte(mm, NULL, orig_page, orig_pte);
        return -12;
    }

    INIT_LIST_HEAD(&m->list);
    m->mm = mm;
    m->orig_page = orig_page;
    m->recomp_page = recomp_page;
    m->pfn_original = (ret == 0) ? pfn : 0;
    m->pte_original = (ret == 0) ? orig_pte : 0;
    atomic_set(&m->refcount, 1);
    m->dead = false;
    m->pte_stripped = (ret == 0);

    if (!m->pte_stripped)
        pr_info("recompile: deferred strip for %lx (PTE absent, will strip on first fault-in)\n",
                orig_page);

    spin_lock(&global_lock);
    list_add(&m->list, &mapping_list);
    atomic_inc(&active_mapping_count);
    spin_unlock(&global_lock);

    pr_info("recompile: registered mapping: %lx -> %lx (pid mm=%px)\n",
            orig_page, recomp_page, mm);
    return 0;
}

int rc_do_release(void *mm, unsigned long orig_addr)
{
    unsigned long orig_page = orig_addr & PAGE_MASK;
    struct recompile_mapping *m;
    bool was_in_list = false;
    int expected_refs;

    m = rc_find_mapping(mm, orig_page);
    if (!m) {
        pr_err("recompile: no mapping for page %lx\n", orig_page);
        return -2;
    }

    spin_lock(&global_lock);
    m->dead = true;
    was_in_list = !list_empty(&m->list);
    if (was_in_list) {
        list_del_init(&m->list);
        atomic_dec(&active_mapping_count);
    }
    spin_unlock(&global_lock);

    expected_refs = 1 + (was_in_list ? 1 : 0);
    {
        int wait = 0;
        while (1) {
            int rc = atomic_read(&m->refcount);
            if (rc <= expected_refs)
                break;
            if (++wait > 2000000) {
                pr_warn("recompile: release drain timeout (refs=%d expected=%d)\n",
                        rc, expected_refs);
                break;
            }
            cpu_relax();
        }
    }

    if (m->pte_stripped) {
        /* Use NULL vma to avoid find_vma which requires mmap_lock */
        u64 *ptep = rc_get_user_pte(mm, orig_page);
        if (ptep)
            rc_write_user_pte(mm, NULL, orig_page, ptep, m->pte_original, true);
        m->pte_stripped = false;
    }

    pr_info("recompile: released mapping: %lx (mm=%px)\n", orig_page, mm);

    if (was_in_list)
        rc_mapping_put(m);
    rc_mapping_put(m);
    return 0;
}

int rc_teardown_mappings_for_mm(void *mm, const char *reason, bool skip_pte_restore)
{
    struct recompile_mapping *m;
    struct list_head *pos, *tmp;
    int count = 0;

    while (1) {
        m = NULL;
        spin_lock(&global_lock);
        list_for_each_safe(pos, tmp, &mapping_list) {
            struct recompile_mapping *entry =
                container_of(pos, struct recompile_mapping, list);
            if (mm && entry->mm != mm)
                continue;
            if (entry->dead)
                continue;
            entry->dead = true;
            list_del_init(&entry->list);
            atomic_dec(&active_mapping_count);
            m = entry;
            break;
        }
        spin_unlock(&global_lock);

        if (!m)
            break;

        {
            int wait = 0;
            while (1) {
                int rc = atomic_read(&m->refcount);
                if (rc <= 1)
                    break;
                if (++wait > 2000000) {
                    pr_warn("recompile: [%s] drain timeout for %lx (refs=%d)\n",
                            reason, m->orig_page, rc);
                    break;
                }
                cpu_relax();
            }
        }

        if (!skip_pte_restore && m->mm && m->pte_stripped && m->pte_original) {
            /* Use NULL vma to avoid find_vma which requires mmap_lock */
            u64 *ptep = rc_get_user_pte(m->mm, m->orig_page);
            if (ptep)
                rc_write_user_pte(m->mm, NULL, m->orig_page, ptep, m->pte_original, true);
        }

        pr_info("recompile: [%s] cleaned mapping %lx->%lx\n",
                reason, m->orig_page, m->recomp_page);
        rc_mapping_put(m);
        count++;
    }

    return count;
}
