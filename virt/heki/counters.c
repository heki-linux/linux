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

static inline unsigned long heki_permissions(struct heki_counters *counters)
{
	unsigned long permissions;

	if (!counters)
		return heki_default_permissions();

	permissions = 0;
	if (counters->read)
		permissions |= MEM_ATTR_READ;
	if (counters->write)
		permissions |= MEM_ATTR_WRITE;
	if (counters->execute)
		permissions |= MEM_ATTR_EXEC;
	if (!permissions)
		permissions = heki_default_permissions();
	return permissions;
}

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

static void heki_check_counters(struct heki_counters *counters,
				unsigned long permissions)
{
	/*
	 * If a permission has been added to a PTE directly, it will not be
	 * reflected in the counters. Adjust for that. This is a bit of a
	 * hack, really.
	 */
	if ((permissions & MEM_ATTR_READ) && !counters->read)
		counters->read++;
	if ((permissions & MEM_ATTR_WRITE) && !counters->write)
		counters->write++;
	if ((permissions & MEM_ATTR_EXEC) && !counters->execute)
		counters->execute++;
}

void heki_callback(struct heki_args *args)
{
	/* The VA is only for debug. It is not really used in this function. */
	unsigned long va;
	phys_addr_t pa, pa_end;
	unsigned long permissions, existing, new;
	void **entry;
	struct heki_counters *counters;
	unsigned int ignore;
	bool protect_memory;

	if (!pfn_valid(args->pa >> PAGE_SHIFT))
		return;

	permissions = heki_flags_to_permissions(args->flags);
	protect_memory = heki.protect_memory;

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

		existing = heki_permissions(counters);

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

		case HEKI_PROTECT_MEMORY:
			if (counters)
				heki_check_counters(counters, permissions);
			existing = 0;
			break;

		default:
			WARN_ON_ONCE(1);
			break;
		}

		new = heki_permissions(counters) | args->set_global;

		/*
		 * To be able to use a pool of allocated memory for new
		 * executable or read-only mappings (e.g., kernel module
		 * loading), ignores immutable attribute if memory can be
		 * changed.
		 */
		if (new & MEM_ATTR_WRITE)
			new &= ~MEM_ATTR_IMMUTABLE;

		if (protect_memory && existing != new)
			heki_add_pa(args, pa, new);
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

	if (args->cmd == HEKI_PROTECT_MEMORY)
		heki.protect_memory = true;

	heki_walk(va, end, heki_callback, args);

	if (args->head)
		heki_apply_permissions(args);

	mutex_unlock(&heki_lock);
}

/*
 * Find the mappings in the given range and initialize permission counters for
 * them. Apply permissions in the host page table.
 */
void heki_map(unsigned long va, unsigned long end)
{
	struct heki_args args = {
		.cmd = HEKI_MAP,
	};

	heki_func(va, end, &args);
}

/*
 * The architecture calls this to protect all guest pages at the end of
 * kernel init. Up to this point, only the counters for guest pages have been
 * updated. No permissions have been applied on the host page table.
 * Now, the permissions will be applied.
 *
 * Beyond this point, the host page table permissions will always be updated
 * whenever the counters are updated.
 */
void heki_protect(unsigned long va, unsigned long end)
{
	struct heki_args args = {
		.cmd = HEKI_PROTECT_MEMORY,
		.set_global = MEM_ATTR_IMMUTABLE,
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
 * them. Apply permissions in the host page table.
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
