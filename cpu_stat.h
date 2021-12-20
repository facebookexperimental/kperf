// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Jakub Kicinski */
/* Copyright Meta Platforms, Inc. and affiliates */

/**
 * DOC: CPU utilization stats
 *
 * Linux CPU use stats read / parsed from procfs.
 *
 * Linux counts CPU use starting at boot and in jiffies so provide helpers
 * to measure CPU use over a period of time and convert it to percentage.
 *
 * All functions take ncpus as returned by get_nprocs_conf(), pass 0 if you
 * don't have get_nprocs_conf() cached.
 *
 * If function returns a pointer to an array that array will be allocated
 * on the heap and has to be explicitly freed. Arrays are sized to ncpus
 * (or get_nprocs_conf()).
 *
 * Example:
 *	struct cpu_stat *s1, *s2, *diffpct;
 *
 *	s1 = cpu_stat_snapshot(0);
 *	sleep(1);
 *	s2 = cpu_stat_snapshot(0);
 *
 *	// Calculate CPU use between s1 was taken and s2 was taken.
 *	cpu_stat_sub(s2, s1, 0);
 *	diffpct = cpu_stat_to_pct00(s2, 0);
 *
 *	// Print percentage of time spent in user context.
 *	printf("usr:%2llu.%02llu\n",
 *	       totpct[i].user / 100, totpct[i].user % 100);
 */
struct cpu_stat {
	unsigned int cpu_id; /* CPU id, not a stat */
	unsigned long long int user; /* sum of user and nice */
	unsigned long long int system;
	unsigned long long int idle;
	unsigned long long int iowait;
	unsigned long long int irq;
	unsigned long long int sirq;
};

struct cpu_stat *cpu_stat_snapshot(int ncpus);
/* convert stats to fractional format, fields multiplied by 10,000 */
struct cpu_stat *cpu_stat_to_pct00(struct cpu_stat *src, int ncpus);
void cpu_stat_sub(struct cpu_stat *dst, struct cpu_stat *op, int ncpus);
