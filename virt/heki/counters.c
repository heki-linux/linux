// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Permissions counters.
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/heki.h>
#include <linux/kvm_mem_attr.h>
#include <linux/mem_table.h>

#include "common.h"

DEFINE_MUTEX(heki_lock);

static void heki_update_counters(struct heki_counters *counters,
				 unsigned long perm, unsigned long set,
				 unsigned long clear)
{
	if (WARN_ON_ONCE(!counters))
		return;

	if ((clear & MEM_ATTR_READ) && (perm & MEM_ATTR_READ))
		counters->read--;
	if ((clear & MEM_ATTR_WRITE) && (perm & MEM_ATTR_WRITE))
		counters->write--;
	if ((clear & MEM_ATTR_EXEC) && (perm & MEM_ATTR_EXEC))
		counters->execute--;

	if ((set & MEM_ATTR_READ) && !(perm & MEM_ATTR_READ))
		counters->read++;
	if ((set & MEM_ATTR_WRITE) && !(perm & MEM_ATTR_WRITE))
		counters->write++;
	if ((set & MEM_ATTR_EXEC) && !(perm & MEM_ATTR_EXEC))
		counters->execute++;
}

static struct heki_counters *heki_create_counters(struct mem_table *table,
						  phys_addr_t pa)
{
	struct heki_counters *counters;
	void **entry;

	entry = mem_table_create(table, pa);
	if (WARN_ON(!entry))
		return NULL;

	counters = kzalloc(sizeof(*counters), GFP_KERNEL);
	if (WARN_ON(!counters))
		return NULL;

	*entry = counters;
	return counters;
}

void heki_callback(struct heki_args *args)
{
	/* The VA is only for debug. It is not really used in this function. */
	unsigned long va;
	phys_addr_t pa, pa_end;
	unsigned long permissions;
	void **entry;
	struct heki_counters *counters;
	unsigned int ignore;

	if (!pfn_valid(args->pa >> PAGE_SHIFT))
		return;

	permissions = heki_flags_to_permissions(args->flags);

	/*
	 * Handle counters for a leaf entry in the kernel page table.
	 */
	pa_end = args->pa + args->size;
	for (pa = args->pa, va = args->va; pa < pa_end;
	     pa += PAGE_SIZE, va += PAGE_SIZE) {
		entry = mem_table_find(heki.counters, pa, &ignore);
		if (entry)
			counters = *entry;
		else
			counters = NULL;

		switch (args->cmd) {
		case HEKI_MAP:
			if (!counters)
				counters =
					heki_create_counters(heki.counters, pa);
			heki_update_counters(counters, 0, permissions, 0);
			break;

		case HEKI_UPDATE:
			if (!counters)
				continue;
			heki_update_counters(counters, permissions, args->set,
					     args->clear);
			break;

		case HEKI_UNMAP:
			if (WARN_ON_ONCE(!counters))
				break;
			heki_update_counters(counters, permissions, 0,
					     permissions);
			break;

		default:
			WARN_ON_ONCE(1);
			break;
		}
	}
}

static void heki_func(unsigned long va, unsigned long end,
		      struct heki_args *args)
{
	if (!heki.counters || va >= end)
		return;

	va = ALIGN_DOWN(va, PAGE_SIZE);
	end = ALIGN(end, PAGE_SIZE);

	mutex_lock(&heki_lock);

	heki_walk(va, end, heki_callback, args);

	mutex_unlock(&heki_lock);
}

/*
 * Find the mappings in the given range and initialize permission counters for
 * them.
 */
void heki_map(unsigned long va, unsigned long end)
{
	struct heki_args args = {
		.cmd = HEKI_MAP,
	};

	heki_func(va, end, &args);
}

/*
 * Find the mappings in the given range and update permission counters for
 * them. Apply permissions in the host page table.
 */
void heki_update(unsigned long va, unsigned long end, unsigned long set,
		 unsigned long clear)
{
	struct heki_args args = {
		.cmd = HEKI_UPDATE,
		.set = set,
		.clear = clear,
	};

	heki_func(va, end, &args);
}

/*
 * Find the mappings in the given range and revert the permission counters for
 * them.
 */
void heki_unmap(unsigned long va, unsigned long end)
{
	struct heki_args args = {
		.cmd = HEKI_UNMAP,
	};

	heki_func(va, end, &args);
}

/*
 * Permissions counters are associated with each guest page using the
 * Memory Table feature. Initialize the permissions counters here.
 * Note that we don't support large page entries for counters because
 * it is difficult to merge/split counters for large pages.
 */

static void heki_counters_free(void *counters)
{
	kfree(counters);
}

static struct mem_table_ops heki_counters_ops = {
	.free = heki_counters_free,
};

__init void heki_counters_init(void)
{
	heki.counters = mem_table_alloc(&heki_counters_ops);
	WARN_ON(!heki.counters);
}
