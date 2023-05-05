// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common code
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <kunit/test.h>
#include <linux/cache.h>
#include <linux/heki.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/set_memory.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "heki-guest: " fmt

static bool heki_enabled __ro_after_init = true;

struct heki heki = {};

struct heki_pa_range *heki_alloc_pa_ranges(struct heki_va_range *va_ranges,
					   int num_ranges)
{
	struct heki_pa_range *pa_ranges, *pa_range;
	struct heki_va_range *va_range;
	u64 attributes;
	size_t size;
	int i;

	size = PAGE_ALIGN(sizeof(struct heki_pa_range) * num_ranges);
	pa_ranges = alloc_pages_exact(size, GFP_KERNEL);
	if (!pa_ranges)
		return NULL;

	for (i = 0; i < num_ranges; i++) {
		va_range = &va_ranges[i];
		pa_range = &pa_ranges[i];

		pa_range->gfn_start = PFN_DOWN(__pa_symbol(va_range->va_start));
		pa_range->gfn_end = PFN_UP(__pa_symbol(va_range->va_end)) - 1;
		pa_range->attributes = va_range->attributes;

		/*
		 * WARNING:
		 * Leaks addresses, should only be kept for development.
		 */
		attributes = pa_range->attributes;
		pr_warn("Configuring GFN 0x%llx-0x%llx with %s\n",
			pa_range->gfn_start, pa_range->gfn_end,
			(attributes & HEKI_ATTR_MEM_NOWRITE) ? "[nowrite]" :
							       "");
	}

	return pa_ranges;
}

void heki_free_pa_ranges(struct heki_pa_range *pa_ranges, int num_ranges)
{
	size_t size;

	size = PAGE_ALIGN(sizeof(struct heki_pa_range) * num_ranges);
	free_pages_exact(pa_ranges, size);
}

void __init heki_early_init(void)
{
	if (!heki_enabled) {
		pr_warn("Disabled\n");
		return;
	}
	pr_warn("Enabled\n");

	heki_arch_init();
}

#ifdef CONFIG_HEKI_TEST

/* Heki test data */

/* Takes two pages to not change permission of other read-only pages. */
const char heki_test_const_buf[PAGE_SIZE * 2] = {};
char heki_test_ro_after_init_buf[PAGE_SIZE * 2] __ro_after_init = {};

long heki_test_exec_data(long);
void _test_exec_data_end(void);

/* Used to test ROP execution against the .rodata section. */
/* clang-format off */
asm(
".pushsection .rodata;" // NOT .text section
".global heki_test_exec_data;"
".type heki_test_exec_data, @function;"
"heki_test_exec_data:"
ASM_ENDBR
"movq %rdi, %rax;"
"inc %rax;"
ASM_RET
".size heki_test_exec_data, .-heki_test_exec_data;"
"_test_exec_data_end:"
".popsection");
/* clang-format on */

static void heki_test_cr_disable_smep(struct kunit *test)
{
	unsigned long cr4;

	/* SMEP should be initially enabled. */
	KUNIT_ASSERT_TRUE(test, __read_cr4() & X86_CR4_SMEP);

	kunit_warn(test,
		   "Starting control register pinning tests with SMEP check\n");

	/*
	 * Trying to disable SMEP, bypassing kernel self-protection by not
	 * using cr4_clear_bits(X86_CR4_SMEP).
	 */
	cr4 = __read_cr4() & ~X86_CR4_SMEP;
	asm volatile("mov %0,%%cr4" : "+r"(cr4) : : "memory");

	/* SMEP should still be enabled. */
	KUNIT_ASSERT_TRUE(test, __read_cr4() & X86_CR4_SMEP);
}

static inline void print_addr(struct kunit *test, const char *const buf_name,
			      void *const buf)
{
	const pte_t pte = *virt_to_kpte((unsigned long)buf);
	const phys_addr_t paddr = slow_virt_to_phys(buf);
	bool present = pte_flags(pte) & (_PAGE_PRESENT);
	bool accessible = pte_accessible(&init_mm, pte);

	kunit_warn(
		test,
		"%s vaddr:%llx paddr:%llx exec:%d write:%d present:%d accessible:%d\n",
		buf_name, (unsigned long long)buf, paddr, !!pte_exec(pte),
		!!pte_write(pte), present, accessible);
}

extern int kernel_set_to_readonly;

static void heki_test_write_to_rodata(struct kunit *test,
				      const char *const buf_name,
				      char *const ro_buf)
{
	print_addr(test, buf_name, (void *)ro_buf);
	KUNIT_EXPECT_EQ(test, 0, *ro_buf);

	kunit_warn(
		test,
		"Bypassing kernel self-protection: mark memory as writable\n");
	kernel_set_to_readonly = 0;
	/*
	 * Removes execute permission that might be set by bugdoor-exec,
	 * because change_page_attr_clear() is not use by set_memory_rw().
	 * This is required since commit 652c5bf380ad ("x86/mm: Refuse W^X
	 * violations").
	 */
	KUNIT_ASSERT_FALSE(test, set_memory_nx((unsigned long)PTR_ALIGN_DOWN(
						       ro_buf, PAGE_SIZE),
					       1));
	KUNIT_ASSERT_FALSE(test, set_memory_rw((unsigned long)PTR_ALIGN_DOWN(
						       ro_buf, PAGE_SIZE),
					       1));
	kernel_set_to_readonly = 1;

	kunit_warn(test, "Trying memory write\n");
	*ro_buf = 0x11;
	KUNIT_EXPECT_EQ(test, 0, *ro_buf);
	kunit_warn(test, "New content: 0x%02x\n", *ro_buf);
}

static void heki_test_write_to_const(struct kunit *test)
{
	heki_test_write_to_rodata(test, "const_buf",
				  (void *)heki_test_const_buf);
}

static void heki_test_write_to_ro_after_init(struct kunit *test)
{
	heki_test_write_to_rodata(test, "ro_after_init_buf",
				  (void *)heki_test_ro_after_init_buf);
}

typedef long test_exec_t(long);

static void heki_test_exec(struct kunit *test)
{
	const size_t exec_size = 7;
	unsigned long nx_page_start = (unsigned long)PTR_ALIGN_DOWN(
		(const void *const)heki_test_exec_data, PAGE_SIZE);
	unsigned long nx_page_end = (unsigned long)PTR_ALIGN(
		(const void *const)heki_test_exec_data + exec_size, PAGE_SIZE);
	test_exec_t *exec = (test_exec_t *)heki_test_exec_data;
	long ret;

	/* Starting non-executable memory tests. */
	print_addr(test, "test_exec_data", heki_test_exec_data);

	kunit_warn(
		test,
		"Bypassing kernel-self protection: mark memory as executable\n");
	kernel_set_to_readonly = 0;
	KUNIT_ASSERT_FALSE(test,
			   set_memory_rox(nx_page_start,
					  PFN_UP(nx_page_end - nx_page_start)));
	kernel_set_to_readonly = 1;

	kunit_warn(
		test,
		"Trying to execute data (ROP) in (initially) non-executable memory\n");
	ret = exec(3);

	/* This should not be reached because of the uncaught page fault. */
	KUNIT_EXPECT_EQ(test, 3, ret);
	kunit_warn(test, "Result of execution: 3 + 1 = %ld\n", ret);
}

const struct kunit_case heki_test_cases[] = {
	KUNIT_CASE(heki_test_cr_disable_smep),
	KUNIT_CASE(heki_test_write_to_const),
	KUNIT_CASE(heki_test_write_to_ro_after_init),
	KUNIT_CASE(heki_test_exec),
	{}
};

static unsigned long heki_test __ro_after_init;

static int __init parse_heki_test_config(char *str)
{
	if (kstrtoul(str, 10, &heki_test) ||
	    heki_test > (ARRAY_SIZE(heki_test_cases) - 1))
		pr_warn("Invalid option string for heki_test: '%s'\n", str);
	return 1;
}

__setup("heki_test=", parse_heki_test_config);

static void heki_run_test(void)
{
	struct kunit_case heki_test_case[2] = {};
	struct kunit_suite heki_test_suite = {
		.name = "heki",
		.test_cases = heki_test_case,
	};
	struct kunit_suite *const test_suite = &heki_test_suite;

	if (!kunit_enabled() || heki_test == 0 ||
	    heki_test >= ARRAY_SIZE(heki_test_cases))
		return;

	pr_warn("Running test #%lu\n", heki_test);
	heki_test_case[0] = heki_test_cases[heki_test - 1];
	__kunit_test_suites_init(&test_suite, 1);
}

#else /* CONFIG_HEKI_TEST */

static inline void heki_run_test(void)
{
}

#endif /* CONFIG_HEKI_TEST */

void heki_late_init(void)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	int ret;

	if (!heki_enabled)
		return heki_run_test();

	if (!heki.static_ranges) {
		pr_warn("Architecture did not initialize static ranges\n");
		return;
	}

	if (!hypervisor) {
		/* This happens for kernels running on bare metal as well. */
		pr_warn("No hypervisor support\n");
		goto out;
	}

	/* Protects statically defined sections in the host page table. */
	ret = hypervisor->protect_ranges(heki.static_ranges,
					 heki.num_static_ranges);
	if (WARN(ret, "Failed to protect static sections: %d\n", ret))
		goto out;
	pr_warn("Static sections protected\n");

	/*
	 * Locks control registers so a compromised guest cannot change
	 * them.
	 */
	ret = hypervisor->lock_crs();
	if (WARN(ret, "Failed to lock control registers: %d\n", ret))
		goto out;
	pr_warn("Control registers locked\n");

	heki_run_test();

out:
	heki_free_pa_ranges(heki.static_ranges, heki.num_static_ranges);
	heki.static_ranges = NULL;
	heki.num_static_ranges = 0;
}

static int __init heki_parse_config(char *str)
{
	if (strtobool(str, &heki_enabled))
		pr_warn("Invalid option string for heki: '%s'\n", str);
	return 1;
}

__setup("heki=", heki_parse_config);
