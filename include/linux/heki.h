/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Definitions
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef __HEKI_H__
#define __HEKI_H__

#include <linux/kvm_types.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>

#ifdef CONFIG_HEKI

/*
 * This structure keeps track of the collective permissions for a guest page
 * across all of its mappings.
 */
struct heki_counters {
	int read;
	int write;
	int execute;
};

/*
 * This structure contains a guest physical range and its permissions (RWX).
 */
struct heki_pages {
	gpa_t pa;
	gpa_t epa;
	unsigned long permissions;
};

/*
 * Guest ranges are passed to the VMM or hypervisor so they can be authenticated
 * and their permissions can be set in the host page table. When an array of
 * these is passed to the Hypervisor or VMM, the array must be in physically
 * contiguous memory.
 *
 * This struct occupies one page. In each page, an array of guest ranges can
 * be passed. A guest request to the VMM/Hypervisor may contain a list of
 * these structs (linked by "next_pa").
 */
struct heki_page_list {
	struct heki_page_list *next;
	gpa_t next_pa;
	unsigned long npages;
	struct heki_pages pages[];
};

/*
 * A hypervisor that supports Heki will instantiate this structure to
 * provide hypervisor specific functions for Heki.
 */
struct heki_hypervisor {
	int (*lock_crs)(void); /* Lock control registers. */
};

/*
 * If the active hypervisor supports Heki, it will plug its heki_hypervisor
 * pointer into this heki structure.
 *
 * During guest kernel boot, permissions counters for each guest page are
 * initialized based on the page's current permissions.
 */
struct heki {
	struct heki_hypervisor *hypervisor;
	struct mem_table *counters;
};

enum heki_cmd {
	HEKI_MAP,
};

/*
 * The kernel page table is walked to locate kernel mappings. For each
 * mapping, a callback function is called. The table walker passes information
 * about the mapping to the callback using this structure.
 */
struct heki_args {
	/* Information passed by the table walker to the callback. */
	unsigned long va;
	phys_addr_t pa;
	size_t size;
	unsigned long flags;

	/* Command passed by caller. */
	enum heki_cmd cmd;
};

/* Callback function called by the table walker. */
typedef void (*heki_func_t)(struct heki_args *args);

extern struct heki heki;
extern bool heki_enabled;

extern bool __read_mostly enable_mbec;

void heki_early_init(void);
void heki_late_init(void);
void heki_counters_init(void);
void heki_walk(unsigned long va, unsigned long va_end, heki_func_t func,
	       struct heki_args *args);
void heki_map(unsigned long va, unsigned long end);

/* Arch-specific functions. */
void heki_arch_early_init(void);
unsigned long heki_flags_to_permissions(unsigned long flags);

#else /* !CONFIG_HEKI */

static inline void heki_early_init(void)
{
}
static inline void heki_late_init(void)
{
}
static inline void heki_map(unsigned long va, unsigned long end)
{
}

#endif /* CONFIG_HEKI */

#endif /* __HEKI_H__ */
