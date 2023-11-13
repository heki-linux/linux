// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common code
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/heki.h>

#include "common.h"

bool heki_enabled __ro_after_init = true;
struct heki heki;

/*
 * Must be called after kmem_cache_init().
 */
__init void heki_early_init(void)
{
	if (!heki_enabled) {
		pr_warn("Heki is not enabled\n");
		return;
	}

	/*
	 * Static addresses (see heki_arch_early_init) are not compatible with
	 * KASLR. This will be handled in a next patch series.
	 */
	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
		pr_warn("Heki is disabled because KASLR is not supported yet\n");
		return;
	}

	pr_warn("Heki is enabled\n");

	if (!heki.hypervisor) {
		/* This happens for kernels running on bare metal as well. */
		pr_warn("No support for Heki in the active hypervisor\n");
		return;
	}
	pr_warn("Heki is supported by the active Hypervisor\n");

	heki_counters_init();
	heki_arch_early_init();
}

/*
 * Must be called after mark_readonly().
 */
void heki_late_init(void)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;

	if (!heki.counters)
		return;

	/* Locks control registers so a compromised guest cannot change them. */
	if (WARN_ON(hypervisor->lock_crs()))
		return;

	pr_warn("Control registers locked\n");

	heki_arch_late_init();
}

/*
 * Build a list of guest pages with their permissions. This list will be
 * passed to the VMM/Hypervisor to set these permissions in the host page
 * table.
 */
void heki_add_pa(struct heki_args *args, phys_addr_t pa,
		 unsigned long permissions)
{
	struct heki_page_list *list = args->head;
	struct heki_pages *hpage;
	u64 max_pages;
	struct page *page;
	bool new = false;

	max_pages = (PAGE_SIZE - sizeof(*list)) / sizeof(*hpage);
again:
	if (!list || list->npages == max_pages) {
		page = alloc_page(GFP_KERNEL);
		if (WARN_ON_ONCE(!page))
			return;

		list = page_address(page);
		list->npages = 0;
		list->next_pa = args->head_pa;
		list->next = args->head;

		args->head = list;
		args->head_pa = page_to_pfn(page) << PAGE_SHIFT;
		new = true;
	}

	hpage = &list->pages[list->npages];
	if (new) {
		hpage->pa = pa;
		hpage->epa = pa + PAGE_SIZE;
		hpage->permissions = permissions;
		return;
	}

	if (pa == hpage->epa && permissions == hpage->permissions) {
		hpage->epa += PAGE_SIZE;
		return;
	}

	list->npages++;
	new = true;
	goto again;
}

void heki_apply_permissions(struct heki_args *args)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	struct heki_page_list *list = args->head;
	phys_addr_t list_pa = args->head_pa;
	struct page *page;
	int ret;

	if (!list)
		return;

	/* The very last one must be included. */
	list->npages++;

	/* Protect guest memory in the host page table. */
	ret = hypervisor->protect_memory(list_pa);
	if (ret) {
		pr_warn("Failed to set memory permission\n");
		return;
	}

	/* Free all the pages in the page list. */
	while (list) {
		page = pfn_to_page(list_pa >> PAGE_SHIFT);
		list_pa = list->next_pa;
		list = list->next;
		__free_pages(page, 0);
	}
}

static int __init heki_parse_config(char *str)
{
	if (strtobool(str, &heki_enabled))
		pr_warn("Invalid option string for heki: '%s'\n", str);
	return 1;
}
__setup("heki=", heki_parse_config);
