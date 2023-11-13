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
#include <linux/mm.h>
#include <linux/memblock.h>
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
	int (*protect_memory)(gpa_t pa); /* Protect guest memory */
};

/*
 * If the active hypervisor supports Heki, it will plug its heki_hypervisor
 * pointer into this heki structure.
 *
 * During guest kernel boot, permissions counters for each guest page are
 * initialized based on the page's current permissions. Beyond this point,
 * the counters are updated whenever:
 *
 *	- a page is mapped into the kernel address space
 *	- a page is unmapped from the kernel address space
 *	- permissions are changed for a mapped page
 *
 * At the end of kernel boot (before kicking off the init process), the
 * permissions for guest pages are applied to the host page table.
 *
 * Beyond that point, the counters and host page table permissions are updated
 * whenever:
 *
 *	- a guest page is mapped into the kernel address space
 *	- a guest page is unmapped from the kernel address space
 *	- permissions are changed for a mapped guest page
 */
struct heki {
	struct heki_hypervisor *hypervisor;
	struct mem_table *counters;
	bool protect_memory;
};

enum heki_cmd {
	HEKI_MAP,
	HEKI_UPDATE,
	HEKI_UNMAP,
	HEKI_PROTECT_MEMORY,
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

	/* Permissions passed by heki_update(). */
	unsigned long set;
	unsigned long set_global;
	unsigned long clear;

	/* Page list is built by the callback. */
	struct heki_page_list *head;
	phys_addr_t head_pa;
};

/* Callback function called by the table walker. */
typedef void (*heki_func_t)(struct heki_args *args);

extern struct heki heki;
extern bool heki_enabled;
extern struct mutex heki_lock;

extern bool __read_mostly enable_mbec;

void heki_early_init(void);
void heki_late_init(void);
void heki_counters_init(void);
void heki_walk(unsigned long va, unsigned long va_end, heki_func_t func,
	       struct heki_args *args);
void heki_map(unsigned long va, unsigned long end);
void heki_update(unsigned long va, unsigned long end, unsigned long set,
		 unsigned long clear);
void heki_unmap(unsigned long va, unsigned long end);
void heki_callback(struct heki_args *args);
void heki_protect(unsigned long va, unsigned long end);
void heki_add_pa(struct heki_args *args, phys_addr_t pa,
		 unsigned long permissions);
void heki_apply_permissions(struct heki_args *args);
void heki_run_test(void);

/* Arch-specific functions. */
void heki_arch_early_init(void);
void heki_arch_late_init(void);
unsigned long heki_flags_to_permissions(unsigned long flags);
void heki_pgprot_to_permissions(pgprot_t prot, unsigned long *set,
				unsigned long *clear);
void heki_text_poke_start(struct page **pages, int npages, pgprot_t prot);
void heki_text_poke_end(struct page **pages, int npages, pgprot_t prot);
unsigned long heki_default_permissions(void);

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
static inline void heki_update(unsigned long va, unsigned long end,
			       unsigned long set, unsigned long clear)
{
}
static inline void heki_unmap(unsigned long va, unsigned long end)
{
}

/* Arch-specific functions. */
static inline void heki_text_poke_start(struct page **pages, int npages,
					pgprot_t prot)
{
}
static inline void heki_text_poke_end(struct page **pages, int npages,
				      pgprot_t prot)
{
}

#endif /* CONFIG_HEKI */

#endif /* __HEKI_H__ */
