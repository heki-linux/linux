/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Memory table feature - Definitions.
 *
 * Copyright © 2023 Microsoft Corporation.
 */

#ifndef __MEM_TABLE_H__
#define __MEM_TABLE_H__

/* clang-format off */

/*
 * The MEM_TABLE bit is set on entries that point to an intermediate table.
 * So, this bit is reserved. This means that pointers to consumer data must
 * be at least two-byte aligned (so the MEM_TABLE bit is 0).
 */
#define MEM_TABLE		BIT(0)
#define IS_LEAF(entry)		!((uintptr_t)entry & MEM_TABLE)

/* clang-format on */

/*
 * A memory table is arranged exactly like a page table. The memory table
 * configuration reflects the hardware page table configuration.
 */

/* Parameters at each level of the memory table hierarchy. */
struct mem_table_level {
	unsigned int number;
	unsigned int nentries;
	unsigned int shift;
	unsigned int mask;
};

struct mem_table {
	struct mem_table_level *level;
	struct mem_table_ops *ops;
	bool changed;
	void *entries[];
};

/* Operations that need to be supplied by a consumer of memory tables. */
struct mem_table_ops {
	void (*free)(void *buf);
};

void mem_table_init(unsigned int base_level);
struct mem_table *mem_table_alloc(struct mem_table_ops *ops);
void mem_table_free(struct mem_table *table);
void **mem_table_create(struct mem_table *table, phys_addr_t pa);
void **mem_table_find(struct mem_table *table, phys_addr_t pa,
		      unsigned int *level_num);

#endif /* __MEM_TABLE_H__ */
