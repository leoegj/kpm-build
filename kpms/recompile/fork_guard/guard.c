/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/printk.h>
#include <asm/current.h>
#include <linux/sched.h>

#include "../recompile_internal.h"

static bool rc_mm_has_mappings(void *mm)
{
    struct list_head *pos;
    bool found = false;

    if (atomic_read(&active_mapping_count) == 0)
        return false;

    spin_lock(&global_lock);
    list_for_each(pos, &mapping_list) {
        struct recompile_mapping *m =
            container_of(pos, struct recompile_mapping, list);
        if (m->mm == mm && !m->dead && m->pte_stripped) {
            found = true;
            break;
        }
    }
    spin_unlock(&global_lock);
    return found;
}

/*
 * Maximum pages to fix per fork. Should be enough for most use cases.
 * If a process has more mappings, remaining pages stay with UXN set,
 * causing spurious faults (functional but slower).
 */
#define RC_FORK_FIX_MAX_PAGES 64

static void rc_fix_child_ptes(void *child_mm, void *parent_mm)
{
    struct list_head *pos;
    unsigned long pages_to_fix[RC_FORK_FIX_MAX_PAGES];
    int nr_pages = 0;
    int count = 0;
    int i;

    /*
     * Phase 1: Collect page addresses while holding the lock.
     * This avoids UAF by not accessing mapping structs outside the lock.
     */
    spin_lock(&global_lock);
    list_for_each(pos, &mapping_list) {
        struct recompile_mapping *m =
            container_of(pos, struct recompile_mapping, list);
        if (m->mm == parent_mm && !m->dead && m->pte_stripped) {
            if (nr_pages < RC_FORK_FIX_MAX_PAGES) {
                pages_to_fix[nr_pages++] = m->orig_page;
            } else {
                pr_warn("recompile: [fork-fix-child] too many pages, truncating at %d\n",
                        RC_FORK_FIX_MAX_PAGES);
                break;
            }
        }
    }
    spin_unlock(&global_lock);

    if (nr_pages == 0)
        return;

    /*
     * Phase 2: Fix PTEs outside the lock. Safe because we only use
     * the page addresses collected above, not the mapping structs.
     */
    for (i = 0; i < nr_pages; i++) {
        u64 *ptep = rc_get_user_pte(child_mm, pages_to_fix[i]);
        if (ptep) {
            u64 pte_val = *(volatile u64 *)ptep;
            if ((pte_val & PTE_VALID) && (pte_val & PTE_UXN)) {
                rc_set_pte(ptep, pte_val & ~PTE_UXN);
                count++;
            }
        }
    }

    /*
     * Phase 3: Flush TLB for the child mm.
     * The child hasn't started yet, but COW may have populated TLB entries
     * during dup_mmap. A full flush is safe and simple here.
     */
    if (count > 0) {
        if (kfunc_flush_tlb_all) {
            kfunc_flush_tlb_all();
        } else {
            /* Fallback: full TLB invalidate */
            asm volatile("tlbi vmalle1is" ::: "memory");
            asm volatile("dsb ish" ::: "memory");
            asm volatile("isb" ::: "memory");
        }

        atomic_inc(&stat_fork_pause);
        pr_info("recompile: [fork-fix-child] comm=%s child_mm=%px parent_mm=%px pages=%d\n",
                get_task_comm(current), child_mm, parent_mm, count);
    }
}

void before_dup_mmap(hook_fargs2_t *args, void *udata)
{
    void *oldmm = (void *)args->arg1;

    args->local.data0 = 0;

    if (atomic_read(&active_mapping_count) == 0) {
        atomic_inc(&stat_fork_skipped);
        return;
    }

    if (!oldmm || !rc_mm_has_mappings(oldmm)) {
        atomic_inc(&stat_fork_skipped);
        return;
    }

    args->local.data0 = 1;
}

void after_dup_mmap(hook_fargs2_t *args, void *udata)
{
    void *child_mm = (void *)args->arg0;
    void *parent_mm = (void *)args->arg1;

    if (!args->local.data0 || !child_mm || !parent_mm)
        return;

    RC_HANDLER_ENTER();
    rc_fix_child_ptes(child_mm, parent_mm);
    RC_HANDLER_EXIT();
}

static inline u64 rc_extract_clone_flags(hook_fargs8_t *args)
{
    unsigned long arg3 = (unsigned long)args->arg3;

    if (arg3 && rc_is_kva(arg3)) {
        u64 flags;
        if (rc_safe_read_u64(arg3, &flags))
            return flags;
    }

    return (u64)args->arg0;
}

void before_copy_process(hook_fargs8_t *args, void *udata)
{
    void *parent_mm;
    u64 clone_flags;

    args->local.data0 = 0;

    if (atomic_read(&active_mapping_count) == 0) {
        atomic_inc(&stat_fork_skipped);
        return;
    }

    clone_flags = rc_extract_clone_flags(args);
    if (clone_flags & CLONE_VM) {
        atomic_inc(&stat_fork_skipped);
        return;
    }

    parent_mm = kfunc_get_task_mm(current);
    if (!parent_mm) {
        atomic_inc(&stat_fork_skipped);
        return;
    }

    if (!rc_mm_has_mappings(parent_mm)) {
        atomic_inc(&stat_fork_skipped);
        kfunc_mmput(parent_mm);
        return;
    }

    args->local.data0 = (unsigned long)parent_mm;
}

void after_copy_process(hook_fargs8_t *args, void *udata)
{
    void *parent_mm = (void *)args->local.data0;
    void *child_task;
    void *child_mm;

    if (!parent_mm)
        return;

    RC_HANDLER_ENTER();

    child_task = (void *)args->ret;
    if (!child_task || (unsigned long)child_task >= (unsigned long)-4095UL) {
        kfunc_mmput(parent_mm);
        RC_HANDLER_EXIT();
        return;
    }

    child_mm = *(void **)((char *)child_task + task_struct_offset.active_mm_offset);
    if (child_mm && child_mm != parent_mm)
        rc_fix_child_ptes(child_mm, parent_mm);

    kfunc_mmput(parent_mm);
    RC_HANDLER_EXIT();
}
