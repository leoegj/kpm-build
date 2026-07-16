/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Recompile Redirect KPM Module - Header
 *
 * Remove execute permission from original code pages, redirect execution
 * to user-space recompiled pages by modifying PC on instruction abort.
 *
 * Copyright (C) 2024
 */

#ifndef _KPM_RECOMPILE_H_
#define _KPM_RECOMPILE_H_

#include <ktypes.h>
#include <stdbool.h>

/* Page size constants */
#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE - 1))

/* prctl options for recompile */
#define PR_RECOMPILE_REGISTER       0x52430001  /* RC + 1: register page mapping */
#define PR_RECOMPILE_RELEASE        0x52430002  /* RC + 2: release page mapping */
#define PR_RECOMPILE_STATS          0x52430003  /* RC + 3: read one stat counter */
#define PR_RECOMPILE_STATS_RESET    0x52430004  /* RC + 4: reset all stat counters */

/*
 * Stats sub-options for PR_RECOMPILE_STATS:
 *   prctl(PR_RECOMPILE_STATS, 0, stat_id, 0, 0)
 *   Returns: counter value (>=0) or -EINVAL
 */
#define RC_STAT_FORK_PAUSE      0   /* Times fork protection fixed child PTEs (legacy name) */
#define RC_STAT_FORK_RESUME     1   /* Reserved (was: resume count, now unused) */
#define RC_STAT_FORK_SKIPPED    2   /* Times fork hook skipped (fast path / no match) */
#define RC_STAT_FAULT_REDIRECT  3   /* Times PC was redirected on permission fault */
#define RC_STAT_ACTIVE_MAPPINGS 4   /* Current number of active mappings */
#define RC_STAT_MAX             5

/*
 * Maximum number of page mappings per process.
 * Each mapping redirects one 4K page to a recompiled page.
 */
#define RECOMPILE_MAX_MAPPINGS  256

/*
 * Per-page redirect mapping.
 *
 * When execution hits orig_page + offset, PC is redirected to
 * recomp_page + offset (offset preserved within page).
 */
struct recompile_mapping {
    struct list_head list;          /* Linked to global mapping_list */
    void *mm;                       /* Owner mm_struct */
    unsigned long orig_page;        /* Original page base (page-aligned) */
    unsigned long recomp_page;      /* Recompiled page base (page-aligned) */
    unsigned long pfn_original;     /* Original page PFN (for PTE restore) */
    u64 pte_original;               /* Saved original PTE value */
    atomic_t refcount;              /* Reference count (lockless inc/dec) */
    bool dead;                      /* Marked for removal (set under global_lock) */
    bool pte_stripped;              /* X permission stripped from PTE */
};

/* PTE bits */
#ifndef PTE_VALID
#define PTE_VALID           (1UL << 0)
#endif
#ifndef PTE_TYPE_PAGE
#define PTE_TYPE_PAGE       (3UL << 0)
#endif
#ifndef PTE_USER
#define PTE_USER            (1UL << 6)
#endif
#ifndef PTE_RDONLY
#define PTE_RDONLY          (1UL << 7)
#endif
#ifndef PTE_SHARED
#define PTE_SHARED          (3UL << 8)
#endif
#ifndef PTE_AF
#define PTE_AF              (1UL << 10)
#endif
#ifndef PTE_NG
#define PTE_NG              (1UL << 11)
#endif
#ifndef PTE_UXN
#define PTE_UXN             (1UL << 54)
#endif
#ifndef PTE_ATTRINDX_NORMAL
#define PTE_ATTRINDX_NORMAL (0UL << 2)
#endif

#endif /* _KPM_RECOMPILE_H_ */
