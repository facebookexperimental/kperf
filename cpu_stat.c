/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Jakub Kicinski */
/* Copyright Meta Platforms, Inc. and affiliates */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/sysinfo.h>

#include "cpu_stat.h"

/* Skip the rest of the line */
static void cpu_stat_nl(FILE *fp)
{
	char c;

	do {
		c = getc(fp);
	} while (c != '\n' && c != EOF);
}

struct cpu_stat *cpu_stat_snapshot(int ncpus)
{
	struct cpu_stat *stats;
	FILE *fp;
	int i;

	if (!ncpus)
		ncpus = get_nprocs_conf();
	if (ncpus < 1)
		return NULL;

	stats = calloc(ncpus, sizeof(*stats));
	if (!stats)
		return NULL;

	fp = fopen("/proc/stat", "r");
	if (!fp)
		goto err_free;

	/* skip first line */
	cpu_stat_nl(fp);

	for (i = 0; i < ncpus; i++) {
		unsigned long long int nice;

		fscanf(fp, "cpu%u %llu %llu %llu %llu %llu %llu %llu",
		       &stats[i].cpu_id,
		       &stats[i].user, &nice,
		       &stats[i].system,
		       &stats[i].idle,
		       &stats[i].iowait,
		       &stats[i].irq,
		       &stats[i].sirq);
		stats[i].user += nice;
		cpu_stat_nl(fp);
	}

	fclose(fp);
	return stats;

err_free:
	free(stats);
	return NULL;
}

/* dst -= op; */
void cpu_stat_sub(struct cpu_stat *dst, struct cpu_stat *op, int ncpus)
{
	int i;

	if (!ncpus)
		ncpus = get_nprocs_conf();

	for (i = 0; i < ncpus; i++) {
		dst[i].user -= op[i].user;
		dst[i].system -= op[i].system;
		dst[i].idle -= op[i].idle;
		dst[i].iowait -= op[i].iowait;
		dst[i].irq -= op[i].irq;
		dst[i].sirq -= op[i].sirq;
	}
}

struct cpu_stat *cpu_stat_to_pct00(struct cpu_stat *src, int ncpus)
{
	struct cpu_stat *pct;
	int i;

	if (!ncpus)
		ncpus = get_nprocs_conf();
	if (ncpus < 1)
		return NULL;

	pct = calloc(ncpus, sizeof(*pct));
	if (!pct)
		return NULL;

	for (i = 0; i < ncpus; i++) {
		unsigned long long int total;

		total = src[i].user + src[i].system + src[i].idle +
			src[i].iowait + src[i].irq + src[i].sirq;

		pct[i].cpu_id	= src[i].cpu_id;
		pct[i].user	= src[i].user	* 10000 / total;
		pct[i].system	= src[i].system	* 10000 / total;
		pct[i].idle	= src[i].idle	* 10000 / total;
		pct[i].iowait	= src[i].iowait	* 10000 / total;
		pct[i].irq	= src[i].irq	* 10000 / total;
		pct[i].sirq	= src[i].sirq	* 10000 / total;
	}

	return pct;
}

#ifdef KPERF_UNITS
int main()
{
	struct cpu_stat *stats1, *stats2;
	struct cpu_stat *totpct, *diffpct;
	int i;

	stats1 = cpu_stat_snapshot(0);
	sleep(1);
	stats2 = cpu_stat_snapshot(0);
	totpct = cpu_stat_to_pct00(stats2, 0);

	cpu_stat_sub(stats2, stats1, 0);
	diffpct = cpu_stat_to_pct00(stats2, 0);

	for (i = 0; i < get_nprocs_conf(); i++) {
		printf("%u/%u: usr:%2llu sys:%2llu idl:%2llu\n",
		       i, stats1[i].cpu_id,
		       stats1[i].user,
		       stats1[i].system,
		       stats1[i].idle);
		printf("%u/%u: usr:%2llu.%02llu sys:%2llu.%02llu idl:%2llu.%02llu\n",
		       i, totpct[i].cpu_id,
		       totpct[i].user / 100, totpct[i].user % 100,
		       totpct[i].system / 100, totpct[i].system % 100,
		       totpct[i].idle / 100, totpct[i].idle % 100);
	}
	free(totpct);
	free(diffpct);
	free(stats1);
	free(stats2);

	return 0;
}
#endif
