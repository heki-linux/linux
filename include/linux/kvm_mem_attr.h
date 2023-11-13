/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KVM guest page permissions - Definitions.
 *
 * Copyright © 2023 Microsoft Corporation.
 */
#ifndef __KVM_MEM_ATTR_H__
#define __KVM_MEM_ATTR_H__

#include <linux/kvm_host.h>
#include <linux/kvm_types.h>

/* clang-format off */

#define MEM_ATTR_READ			BIT(0)
#define MEM_ATTR_WRITE			BIT(1)
#define MEM_ATTR_EXEC			BIT(2)
#define MEM_ATTR_IMMUTABLE		BIT(3)

#define MEM_ATTR_PROT ( \
	MEM_ATTR_READ | \
	MEM_ATTR_WRITE | \
	MEM_ATTR_EXEC | \
	MEM_ATTR_IMMUTABLE)

/* clang-format on */

int kvm_permissions_set(struct kvm *kvm, gfn_t gfn_start, gfn_t gfn_end,
			unsigned long heki_attr);
unsigned long kvm_permissions_get(struct kvm *kvm, gfn_t gfn);

#endif /* __KVM_MEM_ATTR_H__ */
