// SPDX-License-Identifier: GPL-2.0
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Arch specific.
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/heki.h>
#include <linux/kvm_mem_attr.h>

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
