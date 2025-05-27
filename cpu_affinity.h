/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef CPU_AFFINITY_H
#define CPU_AFFINITY_H

#define CPU_AFFINITY_MAX 32

struct cpu_affinity {
	/* the start CPUs of the start-end pairs */
	int start[CPU_AFFINITY_MAX];
	/* the end CPUs of the start-end pairs */
	int end[CPU_AFFINITY_MAX];
	/* the total count of pairs added */
	int cnt;
	/* the idx into the current pair */
	int idx;
	/* the last cpu allocated */
	int last_cpu;
	/* total number of cpus */
	int total;
};

int parse_cpu_list(const char *affinity_list, struct cpu_affinity *ca);
int cpu_affinity_alloc_cpu(struct cpu_affinity *ca);

#endif /* CPU_AFFINITY_H */
