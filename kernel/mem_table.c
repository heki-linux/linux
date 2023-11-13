// SPDX-License-Identifier: GPL-2.0-only
/*
 * Memory table feature.
 *
 * This feature can be used by a consumer to associate any arbitrary pointer
 * with a physical page. The feature implements a page table format that
 * mirrors the hardware page table. A leaf entry in the table points to
 * consumer data for that page.
 *
 * The page table format has these advantages:
 *
 *	- The format allows for a sparse representation. This is useful since
 *	  the physical address space can be large and is typically sparsely
 *	  populated in a system.
 *
 *	- A consumer of this feature can choose to populate data just for
 *	  the pages he is interested in.
 *
 *	- Information can be stored for large pages, if a consumer wishes.
 *
 * For instance, for Heki, the guest kernel uses this to create permissions
 * counters for each guest physical page. The permissions counters reflects the
 * collective permissions for a guest physical page across all mappings to that
 * page. This allows the guest to request the hypervisor to set only the
 * necessary permissions for a guest physical page in the EPT (instead of RWX).
 *
 * Copyright © 2023 Microsoft Corporation.
 */

/*
 * Memory table functions use recursion for simplicity. The recursion is bounded
 * by the number of hardware page table levels.
 *
 * Locking is left to the caller of these functions.
 */
#include <linux/heki.h>
#include <linux/mem_table.h>
#include <linux/pgtable.h>

#define TABLE(entry) ((void *)((uintptr_t)entry & ~MEM_TABLE))
#define ENTRY(table) ((void *)((uintptr_t)table | MEM_TABLE))

/*
 * Within this feature, the table levels start from 0. On X86, the base level
 * is not 0.
 */
unsigned int mem_table_base_level __ro_after_init;
unsigned int mem_table_nlevels __ro_after_init;
struct mem_table_level mem_table_levels[CONFIG_PGTABLE_LEVELS] __ro_after_init;

void __init mem_table_init(unsigned int base_level)
{
	struct mem_table_level *level;
	unsigned long shift, delta_shift;
	int physmem_bits;
	int i, max_levels;

	/*
	 * Compute the actual number of levels present. Compute the parameters
	 * for each level.
	 */
	shift = ilog2(PAGE_SIZE);
	physmem_bits = PAGE_SHIFT;
	max_levels = CONFIG_PGTABLE_LEVELS;

	for (i = 0; i < max_levels && physmem_bits < MAX_PHYSMEM_BITS; i++) {
		level = &mem_table_levels[i];

		switch (i) {
		case 0:
			level->nentries = PTRS_PER_PTE;
			break;
		case 1:
			level->nentries = PTRS_PER_PMD;
			break;
		case 2:
			level->nentries = PTRS_PER_PUD;
			break;
		case 3:
			level->nentries = PTRS_PER_P4D;
			break;
		case 4:
			level->nentries = PTRS_PER_PGD;
			break;
		}
		level->number = i;
		level->shift = shift;
		level->mask = level->nentries - 1;

		delta_shift = ilog2(level->nentries);
		shift += delta_shift;
		physmem_bits += delta_shift;
	}
	mem_table_nlevels = i;
	mem_table_base_level = base_level;
}

struct mem_table *mem_table_alloc(struct mem_table_ops *ops)
{
	struct mem_table_level *level;
	struct mem_table *table;

	level = &mem_table_levels[mem_table_nlevels - 1];

	table = kzalloc(struct_size(table, entries, level->nentries),
			GFP_KERNEL);
	if (table) {
		table->level = level;
		table->ops = ops;
		return table;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(mem_table_alloc);

static void _mem_table_free(struct mem_table *table)
{
	struct mem_table_level *level = table->level;
	void **entries = table->entries;
	struct mem_table_ops *ops = table->ops;
	int i;

	for (i = 0; i < level->nentries; i++) {
		if (!entries[i])
			continue;
		if (IS_LEAF(entries[i])) {
			/* The consumer frees the pointer. */
			ops->free(entries[i]);
			continue;
		}
		_mem_table_free(TABLE(entries[i]));
	}
	kfree(table);
}

void mem_table_free(struct mem_table *table)
{
	_mem_table_free(table);
}
EXPORT_SYMBOL_GPL(mem_table_free);

static void **_mem_table_find(struct mem_table *table, phys_addr_t pa,
			      unsigned int *level_number)
{
	struct mem_table_level *level = table->level;
	void **entries = table->entries;
	unsigned long i;

	i = (pa >> level->shift) & level->mask;

	*level_number = level->number;
	if (!entries[i])
		return NULL;

	if (IS_LEAF(entries[i]))
		return &entries[i];

	return _mem_table_find(TABLE(entries[i]), pa, level_number);
}

void **mem_table_find(struct mem_table *table, phys_addr_t pa,
		      unsigned int *level_number)
{
	void **entry;

	entry = _mem_table_find(table, pa, level_number);
	level_number += mem_table_base_level;

	return entry;
}
EXPORT_SYMBOL_GPL(mem_table_find);

static void **_mem_table_create(struct mem_table *table, phys_addr_t pa)
{
	struct mem_table_level *level = table->level;
	void **entries = table->entries;
	unsigned long i;

	table->changed = true;
	i = (pa >> level->shift) & level->mask;

	if (!level->number) {
		/*
		 * Reached the lowest level. Return a pointer to the entry
		 * so that the consumer can populate it.
		 */
		return &entries[i];
	}

	/*
	 * If the entry is NULL, then create a lower level table and make the
	 * entry point to it. Or, if the entry is a leaf, then we need to
	 * split the entry. In this case as well, create a lower level table
	 * to split the entry.
	 */
	if (!entries[i] || IS_LEAF(entries[i])) {
		struct mem_table *next;

		/* Create next level table. */
		level--;
		next = kzalloc(struct_size(table, entries, level->nentries),
			       GFP_KERNEL);
		if (!next)
			return NULL;

		next->level = level;
		next->ops = table->ops;
		next->changed = true;
		entries[i] = ENTRY(next);
	}

	return _mem_table_create(TABLE(entries[i]), pa);
}

void **mem_table_create(struct mem_table *table, phys_addr_t pa)
{
	return _mem_table_create(table, pa);
}
EXPORT_SYMBOL_GPL(mem_table_create);
