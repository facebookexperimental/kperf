#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu_affinity.h"

#define warnx(...) fprintf(stderr, ##__VA_ARGS__)

#define SEGMENT_MAX_LEN 64
#define CPU_MAX_LEN 32

static void cpu_affinity_init(struct cpu_affinity *ca)
{
	ca->idx = 0;
	ca->last_cpu = -1;
	ca->cnt = 0;
	ca->total = 0;
}

static bool cpu_affinity_list_empty(struct cpu_affinity *ca)
{
	return ca->cnt == 0;
}

static int cpu_affinity_add_range(struct cpu_affinity *ca, int start, int end)
{
	if (ca->idx >= CPU_AFFINITY_MAX)
		return -EINVAL;

	ca->start[ca->cnt] = start;
	ca->end[ca->cnt] = end;
	ca->cnt++;
	ca->total += end - start + 1;

	return 0;
}

int cpu_affinity_alloc_cpu(struct cpu_affinity *ca)
{
	int cpu;

	if (ca->idx >= ca->cnt)
		return -EINVAL;

	/* if this is the first allocation, grab the first and return it */
	if (ca->last_cpu == -1) {
		cpu = ca->start[ca->idx];
		goto out;
	}

	/* if next cpu can be allocated from the current start-end pair, then return it */
	if (ca->last_cpu + 1 <= ca->end[ca->idx]) {
		cpu = ca->last_cpu + 1;
		goto out;
	}

	/* return the first cpu from the next pair (if it exists) */
	if (ca->idx == ca->cnt - 1)
		return -EINVAL;

	ca->idx++;
	cpu = ca->start[ca->idx];

out:
	ca->last_cpu = cpu;
	return cpu;
}

static int parse_cpu_list_segment(char *segment, struct cpu_affinity *ca)
{
	int start, end, i;
	char *cpu, *cpub;
	char cpubuf[CPU_MAX_LEN + 1];
	char *tmp;

	start = -1;
	end = -1;
	tmp = NULL;

	if (strlen(segment) >= CPU_MAX_LEN)
		return -EINVAL;

	strncpy(cpubuf, segment, CPU_MAX_LEN);

	for (i = 0, cpu = strtok_r(cpubuf, "-", &cpub); cpu; cpu = strtok_r(NULL, "-", &cpub), i++) {
		tmp = NULL;
		errno = 0;
		if ((i % 2) == 0)
			start = strtol(cpu, &tmp, 10);
		else
			end = strtol(cpu, &tmp, 10);

		if (errno == ERANGE || errno == EINVAL)
			return -errno;
		if (tmp == cpubuf)
			return -EINVAL;

		if (start != -1 && end != -1) {
			/* now that we have both a start and end, add it */
			if (cpu_affinity_add_range(ca, start, end) < 0)
				return -EFAULT;

			start = -1;
			end = -1;
		}
	}

	/* this segment is not a range, let's try to parse it as a single CPU number */
	if (cpu_affinity_list_empty(ca)) {
		tmp = NULL;
		errno = 0;
		start = strtol(cpubuf, &tmp, 10);
		if (errno == ERANGE || errno == EINVAL)
			return -errno;
		if (tmp == cpubuf)
			return -EINVAL;
		end = start;

		if (cpu_affinity_add_range(ca, start, end) < 0)
			return -EFAULT;
	}

	return 0;
}

int parse_cpu_list(const char *affinity_list, struct cpu_affinity *ca)
{
	char *segb, *seg;
	char segbuf[SEGMENT_MAX_LEN + 1];
	int ret;

	if (!affinity_list || !ca)
		return -EINVAL;

	cpu_affinity_init(ca);

	strncpy(segbuf, affinity_list, SEGMENT_MAX_LEN);

	for (seg = strtok_r(segbuf, ",", &segb); seg; seg = strtok_r(NULL, ",", &segb)) {
		ret = parse_cpu_list_segment(seg, ca);
		if (ret < 0)
			return ret;
	}

	/* If it isn't comma-separated, then it might just be a single range or
	 * cpu (e.g., "9" or "9-10")
	 */
	if (cpu_affinity_list_empty(ca)) {
		ret = parse_cpu_list_segment(segbuf, ca);
		if (ret < 0)
			return ret;
	}

	return 0;
}

#ifdef KPERF_UNITS
void __test(const char *str, int *expected, int n)
{
	struct cpu_affinity ca;
	int cpu;
	int i;

	parse_cpu_list(str, &ca);

	printf(" total=%d (%d), ", ca.total, n);
	assert(ca.total == n);

	printf("test: %s, ", str);

	if (n == 0)
		goto out;

	printf("results: ");
	for (i = 0; i < n; i++) {
		cpu = cpu_affinity_alloc_cpu(&ca);
		assert(cpu >= 0);
		assert(i < n);
		printf("%d (%d), ", cpu, expected[i]);
		assert(cpu == expected[i]);
	}

out:
	printf("ok\n");
}

#define test(_str, _exp, _n) ({ printf("%s:", __func__); __test((_str), (_exp), (_n)); })

void test_one_num(void)
{
	char *str = "9";
	int expected[] = { 9 };

	test(str, expected, 1);
}

void test_one_seg(void)
{
	char *str = "5-7";
	int expected[] = { 5, 6, 7 };

	test(str, expected, 3);
}

void test_two_segs(void)
{
	char *str = "1-4,20-21";
	int expected[] = { 1, 2, 3, 4, 20, 21 };

	test(str, expected, 6);
}

void test_nan(void)
{
	char *str = "foobar";
	int expected[] = {};

	test(str, expected, 0);
}

void test_inval(void)
{
	char *str = "1-A";
	int expected[] = {};

	test(str, expected, 0);
}

void test_range(void)
{
	int expected[] = {};

	test("18446744073709551616", expected, 0);
}

int main(void)
{
	test_one_num();
	test_one_seg();
	test_two_segs();
	test_nan();
	test_inval();
	test_range();

	return 0;
}
#endif
