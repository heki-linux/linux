// SPDX-License-Identifier: GPL-2.0
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Arch specific.
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <asm/pgtable.h>
#include <asm/text-patching.h>
#include <linux/heki.h>
#include <linux/kvm_mem_attr.h>
#include <linux/mm.h>

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "heki-guest: " fmt

static unsigned long kernel_va;
static unsigned long kernel_end;
static unsigned long direct_map_va;
static unsigned long direct_map_end;

__init void heki_arch_early_init(void)
{
	/* Kernel virtual address space range, not yet compatible with KASLR. */
	if (pgtable_l5_enabled()) {
		kernel_va = 0xff00000000000000UL;
		kernel_end = 0xffffffffffe00000UL;
		direct_map_va = 0xff11000000000000UL;
		direct_map_end = 0xff91000000000000UL;
	} else {
		kernel_va = 0xffff800000000000UL;
		kernel_end = 0xffffffffffe00000UL;
		direct_map_va = 0xffff888000000000UL;
		direct_map_end = 0xffffc88000000000UL;
	}

	/*
	 * Initialize the counters for all existing kernel mappings except
	 * for direct map.
	 */
	heki_map(kernel_va, direct_map_va);
	heki_map(direct_map_end, kernel_end);
}

void heki_arch_late_init(void)
{
	/*
	 * The permission counters for all existing kernel mappings have
	 * already been updated. Now, walk all the pages, compute their
	 * permissions from the counters and apply the permissions in the
	 * host page table. To accomplish this, we walk the direct map
	 * range.
	 */
	heki_protect(direct_map_va, direct_map_end);
	pr_warn("Guest memory protected\n");
}

unsigned long heki_flags_to_permissions(unsigned long flags)
{
	unsigned long permissions;

	permissions = MEM_ATTR_READ | MEM_ATTR_EXEC;
	if (flags & _PAGE_RW)
		permissions |= MEM_ATTR_WRITE;
	if (flags & _PAGE_NX)
		permissions &= ~MEM_ATTR_EXEC;

	return permissions;
}

void heki_pgprot_to_permissions(pgprot_t prot, unsigned long *set,
				unsigned long *clear)
{
	if (pgprot_val(prot) & _PAGE_RW)
		*set |= MEM_ATTR_WRITE;
	if (pgprot_val(prot) & _PAGE_NX)
		*clear |= MEM_ATTR_EXEC;
}

unsigned long heki_default_permissions(void)
{
	return MEM_ATTR_READ | MEM_ATTR_WRITE;
}

static unsigned long heki_pgprot_to_flags(pgprot_t prot)
{
	unsigned long flags = 0;

	if (pgprot_val(prot) & _PAGE_RW)
		flags |= _PAGE_RW;
	if (pgprot_val(prot) & _PAGE_NX)
		flags |= _PAGE_NX;
	return flags;
}

static void heki_text_poke_common(struct page **pages, int npages,
				  pgprot_t prot, enum heki_cmd cmd)
{
	struct heki_args args = {
		.cmd = cmd,
	};
	unsigned long va = poking_addr;
	int i;

	if (!heki.counters)
		return;

	mutex_lock(&heki_lock);

	for (i = 0; i < npages; i++, va += PAGE_SIZE) {
		args.va = va;
		args.pa = page_to_pfn(pages[i]) << PAGE_SHIFT;
		args.size = PAGE_SIZE;
		args.flags = heki_pgprot_to_flags(prot);
		heki_callback(&args);
	}

	if (args.head)
		heki_apply_permissions(&args);

	mutex_unlock(&heki_lock);
}

void heki_text_poke_start(struct page **pages, int npages, pgprot_t prot)
{
	heki_text_poke_common(pages, npages, prot, HEKI_MAP);
}

void heki_text_poke_end(struct page **pages, int npages, pgprot_t prot)
{
	heki_text_poke_common(pages, npages, prot, HEKI_UNMAP);
}
