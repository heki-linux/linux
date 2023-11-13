// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM guest page permissions - functions.
 *
 * Copyright © 2023 Microsoft Corporation.
 */
#include <linux/kvm_host.h>
#include <linux/kvm_mem_attr.h>

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "kvm: heki: " fmt

/* clang-format off */

static unsigned long kvm_default_permissions =
	MEM_ATTR_READ |
	MEM_ATTR_WRITE |
	MEM_ATTR_EXEC;

static unsigned long kvm_memory_attributes_heki =
	KVM_MEMORY_ATTRIBUTE_HEKI_READ |
	KVM_MEMORY_ATTRIBUTE_HEKI_WRITE |
	KVM_MEMORY_ATTRIBUTE_HEKI_EXEC |
	KVM_MEMORY_ATTRIBUTE_HEKI_IMMUTABLE;

/* clang-format on */

static unsigned long heki_attr_to_kvm_attr(unsigned long heki_attr)
{
	unsigned long kvm_attr = 0;

	if (WARN_ON_ONCE((heki_attr | MEM_ATTR_PROT) != MEM_ATTR_PROT))
		return 0;

	if (heki_attr & MEM_ATTR_READ)
		kvm_attr |= KVM_MEMORY_ATTRIBUTE_HEKI_READ;
	if (heki_attr & MEM_ATTR_WRITE)
		kvm_attr |= KVM_MEMORY_ATTRIBUTE_HEKI_WRITE;
	if (heki_attr & MEM_ATTR_EXEC)
		kvm_attr |= KVM_MEMORY_ATTRIBUTE_HEKI_EXEC;
	if (heki_attr & MEM_ATTR_IMMUTABLE)
		kvm_attr |= KVM_MEMORY_ATTRIBUTE_HEKI_IMMUTABLE;
	return kvm_attr;
}

static unsigned long kvm_attr_to_heki_attr(unsigned long kvm_attr)
{
	unsigned long heki_attr = 0;

	if (kvm_attr & KVM_MEMORY_ATTRIBUTE_HEKI_READ)
		heki_attr |= MEM_ATTR_READ;
	if (kvm_attr & KVM_MEMORY_ATTRIBUTE_HEKI_WRITE)
		heki_attr |= MEM_ATTR_WRITE;
	if (kvm_attr & KVM_MEMORY_ATTRIBUTE_HEKI_EXEC)
		heki_attr |= MEM_ATTR_EXEC;
	if (kvm_attr & KVM_MEMORY_ATTRIBUTE_HEKI_IMMUTABLE)
		heki_attr |= MEM_ATTR_IMMUTABLE;
	return heki_attr;
}

unsigned long kvm_permissions_get(struct kvm *kvm, gfn_t gfn)
{
	unsigned long kvm_attr = 0;

	/*
	 * Retrieve the permissions for a guest page. If not present (i.e., no
	 * attribute), then return default permissions (RWX).  This means
	 * setting permissions to 0 resets them to RWX. We might want to
	 * revisit that in a future version.
	 */
	kvm_attr = kvm_get_memory_attributes(kvm, gfn);
	if (kvm_attr)
		return kvm_attr_to_heki_attr(kvm_attr);
	else
		return kvm_default_permissions;
}
EXPORT_SYMBOL_GPL(kvm_permissions_get);

int kvm_permissions_set(struct kvm *kvm, gfn_t gfn_start, gfn_t gfn_end,
			unsigned long heki_attr)
{
	if ((heki_attr | MEM_ATTR_PROT) != MEM_ATTR_PROT)
		return -EINVAL;

	if (gfn_end <= gfn_start)
		return -EINVAL;

	if (kvm_range_has_memory_attributes(kvm, gfn_start, gfn_end,
					    KVM_MEMORY_ATTRIBUTE_HEKI_IMMUTABLE,
					    false)) {
		pr_warn_ratelimited(
			"Guest tried to change immutable permission for GFNs %llx-%llx\n",
			gfn_start, gfn_end);
		return -EPERM;
	}

	return kvm_vm_set_mem_attributes(kvm, gfn_start, gfn_end,
					 heki_attr_to_kvm_attr(heki_attr),
					 kvm_memory_attributes_heki);
}
EXPORT_SYMBOL_GPL(kvm_permissions_set);
