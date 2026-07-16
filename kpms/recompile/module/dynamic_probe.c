/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/printk.h>
#include <linux/string.h>
#include <asm/current.h>

#include "../recompile_internal.h"
#include "symbol_table.h"

#define RC_KALLSYMS_CB_STYLE_UNKNOWN 0
#define RC_KALLSYMS_CB_STYLE_3ARG    3
#define RC_KALLSYMS_CB_STYLE_4ARG    4
#define RC_KALLSYMS_PROBE_REF_SYM    "_stext"

#define RC_TCR_T1SZ_SHIFT            16
#define RC_TCR_T1SZ_MASK             0x3f
#define RC_TCR_TG1_SHIFT             30
#define RC_TCR_TG1_MASK              0x3
#define RC_TCR_TG1_16K               1
#define RC_TCR_TG1_64K               3

#define RC_PHYSVIRT_TEST_GFP_MASK    0x0cc0

#define RC_VMA_VM_MM_SCAN_START      0x10
#define RC_VMA_VM_MM_SCAN_END        0x80
#define RC_VMA_VM_MM_SCAN_STEP       0x08

#define RC_MM_CONTEXT_ID_SCAN_START  0x100
#define RC_MM_CONTEXT_ID_SCAN_END    0x400
#define RC_MM_CONTEXT_ID_SCAN_STEP   0x08

#define RC_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct lookup_data {
    const char *name;
    unsigned long addr;
};

static int lookup_cb_4arg(void *data, const char *name,
                          struct module *mod, unsigned long addr)
{
    struct lookup_data *ld = data;

    if (strcmp(name, ld->name) == 0) {
        ld->addr = addr;
        return 1;
    }
    return 0;
}

static int lookup_cb_3arg(void *data, const char *name, unsigned long addr)
{
    struct lookup_data *ld = data;

    if (strcmp(name, ld->name) == 0) {
        ld->addr = addr;
        return 1;
    }
    return 0;
}

static int cb_param_style = RC_KALLSYMS_CB_STYLE_UNKNOWN;
static bool cb_style_detected = false;

static void detect_callback_style(void)
{
    struct lookup_data ld;
    unsigned long ref_addr;

    /* Only detect once - this function is called many times during init */
    if (cb_style_detected)
        return;
    cb_style_detected = true;

    if (!kallsyms_on_each_symbol || !kallsyms_lookup_name)
        return;

    ref_addr = kallsyms_lookup_name(RC_KALLSYMS_PROBE_REF_SYM);
    if (!ref_addr)
        return;

    ld.name = RC_KALLSYMS_PROBE_REF_SYM;
    ld.addr = 0;
    kallsyms_on_each_symbol((void *)lookup_cb_4arg, &ld);
    if (ld.addr == ref_addr) {
        cb_param_style = RC_KALLSYMS_CB_STYLE_4ARG;
        pr_info("recompile: kallsyms_on_each_symbol uses 4-param callback\n");
        return;
    }

    ld.addr = 0;
    kallsyms_on_each_symbol((void *)lookup_cb_3arg, &ld);
    if (ld.addr == ref_addr) {
        cb_param_style = RC_KALLSYMS_CB_STYLE_3ARG;
        pr_info("recompile: kallsyms_on_each_symbol uses 3-param callback\n");
        return;
    }

    pr_warn("recompile: could not detect callback style, using kallsyms_lookup_name\n");
}

static unsigned long __lookup_name(const char *name)
{
    struct lookup_data ld = { .name = name, .addr = 0 };

    if (kallsyms_on_each_symbol && cb_param_style == RC_KALLSYMS_CB_STYLE_4ARG) {
        kallsyms_on_each_symbol((void *)lookup_cb_4arg, &ld);
        if (ld.addr)
            return ld.addr;
    } else if (kallsyms_on_each_symbol && cb_param_style == RC_KALLSYMS_CB_STYLE_3ARG) {
        kallsyms_on_each_symbol((void *)lookup_cb_3arg, &ld);
        if (ld.addr)
            return ld.addr;
    } else if (kallsyms_lookup_name) {
        return kallsyms_lookup_name(name);
    }
    return 0;
}

unsigned long lookup_name_safe(const char *name)
{
    unsigned long addr = __lookup_name(name);

    if (addr)
        return addr;

    {
        char noprof_name[128];
        int len = strlen(name);
        if (len + 8 < (int)sizeof(noprof_name)) {
            memcpy(noprof_name, name, len);
            memcpy(noprof_name + len, "_noprof", 8);
            addr = __lookup_name(noprof_name);
        }
    }

    return addr;
}

unsigned long lookup_name_any(const char *const *names, size_t count)
{
    size_t i;

    detect_callback_style();

    for (i = 0; i < count; i++) {
        unsigned long addr;

        if (!names[i] || !names[i][0])
            continue;
        addr = lookup_name_safe(names[i]);
        if (addr)
            return addr;
    }

    return 0;
}

int rc_probe_page_table_config(void)
{
    u64 tcr_el1;
    int t1sz, tg1;
    long long va_bits;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    t1sz = (tcr_el1 >> RC_TCR_T1SZ_SHIFT) & RC_TCR_T1SZ_MASK;
    va_bits = 64 - t1sz;

    tg1 = (tcr_el1 >> RC_TCR_TG1_SHIFT) & RC_TCR_TG1_MASK;
    rc_page_shift = 12;
    if (tg1 == RC_TCR_TG1_16K)
        rc_page_shift = 14;
    else if (tg1 == RC_TCR_TG1_64K)
        rc_page_shift = 16;

    rc_page_level = (va_bits - 4) / (rc_page_shift - 3);
    if (rc_page_level < 3 || rc_page_level > 4) {
        pr_err("recompile: unsupported arm64 page-table geometry: level=%d shift=%d va_bits=%lld\n",
               rc_page_level, rc_page_shift, va_bits);
        return -1;
    }
    page_offset_base = -(1UL << va_bits);

    pr_info("recompile: page_level=%d va_bits=%lld page_shift=%d PAGE_OFFSET=%lx\n",
            rc_page_level, va_bits, rc_page_shift, page_offset_base);
    return 0;
}

int rc_probe_physvirt_translation(void)
{
    kvar_memstart_addr = (typeof(kvar_memstart_addr))
        lookup_name_any(rc_sym_memstart_addr, RC_ARRAY_SIZE(rc_sym_memstart_addr));
    kvar_physvirt_offset = (typeof(kvar_physvirt_offset))
        lookup_name_any(rc_sym_physvirt_offset, RC_ARRAY_SIZE(rc_sym_physvirt_offset));

    if (kvar_physvirt_offset) {
        detected_physvirt_offset = *kvar_physvirt_offset;
        physvirt_offset_valid = 1;
        pr_info("recompile: physvirt_offset=%llx (from symbol)\n",
                (unsigned long long)detected_physvirt_offset);
    }

    pr_info("recompile: __get_free_pages=%px free_pages=%px\n",
            kfunc___get_free_pages, kfunc_free_pages);
    if (kfunc___get_free_pages && kfunc_free_pages) {
        unsigned long test_kva = kfunc___get_free_pages(RC_PHYSVIRT_TEST_GFP_MASK, 0);
        pr_info("recompile: test_kva=%lx\n", test_kva);
        if (test_kva) {
            u64 par;
            asm volatile("at s1e1r, %0" : : "r"(test_kva));
            asm volatile("isb");
            asm volatile("mrs %0, par_el1" : "=r"(par));
            pr_info("recompile: AT par=%llx\n", (unsigned long long)par);
            if (!(par & 1)) {
                unsigned long real_pa = (par & 0x0000FFFFFFFFF000UL) | (test_kva & 0xFFF);
                detected_physvirt_offset = (s64)test_kva - (s64)real_pa;
                physvirt_offset_valid = 1;
                pr_info("recompile: physvirt_offset=%llx (from AT: kva=%lx pa=%lx)\n",
                        (unsigned long long)detected_physvirt_offset, test_kva, real_pa);
            } else {
                pr_warn("recompile: AT translation failed (par=%llx)\n", (unsigned long long)par);
            }
            kfunc_free_pages(test_kva, 0);
        }
    } else {
        pr_info("recompile: skipping AT probe (missing symbols)\n");
    }

    if (!physvirt_offset_valid && !kvar_memstart_addr) {
        pr_err("recompile: no address translation available, refusing to load\n");
        return -1;
    }
    if (!physvirt_offset_valid) {
        pr_info("recompile: memstart_addr symbol at %px, value=%llx, PAGE_OFFSET=%lx (fallback)\n",
                kvar_memstart_addr, (unsigned long long)*kvar_memstart_addr, page_offset_base);
    }

    return 0;
}

int scan_vma_offsets(void)
{
    void *mm;
    void *vma;
    int offset;

    mm = kfunc_get_task_mm(current);
    if (!mm) {
        pr_err("recompile: cannot get current mm for VMA scan\n");
        return -1;
    }

    vma = kfunc_find_vma(mm, 0);
    if (!vma) {
        kfunc_mmput(mm);
        pr_err("recompile: no VMA found in current process\n");
        return -1;
    }

    for (offset = RC_VMA_VM_MM_SCAN_START;
         offset <= RC_VMA_VM_MM_SCAN_END;
         offset += RC_VMA_VM_MM_SCAN_STEP) {
        void *candidate = GET_FIELD(vma, offset, void *);
        if (candidate == mm) {
            vma_vm_mm_offset = offset;
            pr_info("recompile: vma->vm_mm at offset 0x%x\n", offset);
            kfunc_mmput(mm);
            return 0;
        }
    }

    kfunc_mmput(mm);
    pr_err("recompile: vma->vm_mm scan failed\n");
    return -1;
}

int scan_mm_context_id(void)
{
    void *mm;
    u64 ttbr0;
    u64 asid;
    int offset;

    mm = kfunc_get_task_mm(current);
    if (!mm)
        return -1;

    asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
    asid = (ttbr0 >> 48) & 0xFFFF;
    if (asid == 0) {
        kfunc_mmput(mm);
        return -1;
    }

    for (offset = RC_MM_CONTEXT_ID_SCAN_START;
         offset < RC_MM_CONTEXT_ID_SCAN_END;
         offset += RC_MM_CONTEXT_ID_SCAN_STEP) {
        u64 val = *(u64 *)((char *)mm + offset);
        if ((val & 0xFFFF) == asid && val != 0) {
            mm_context_id_offset = offset;
            pr_info("recompile: mm->context.id at offset 0x%x (asid=%llu)\n",
                    offset, asid);
            kfunc_mmput(mm);
            return 0;
        }
    }

    kfunc_mmput(mm);
    return -1;
}
