// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Jakub Kicinski */
/* Copyright Meta Platforms, Inc. and affiliates */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/array_size/array_size.h>
#include <ccan/compiler/compiler.h>
#include <ccan/minmax/minmax.h>
#include <ccan/tal/tal.h>

#include "bipartite_match.h"

#define INIT_STATE_SIZE		8

struct bim_state {
	/* Sizing allocated memory */
	unsigned int max_left;
	unsigned int max_right;
	/* Max vertex indexes seen */
	unsigned int max_used_left;
	unsigned int max_used_right;

	/* Arrays indexed by left_id */
	unsigned int **left_neigh;
	void ***left_neigh_cookie;
	unsigned int *n_left_neigh;
	int *left_match;

	/* Arrays indexed by right_id */
	int *right_match;

	/* Recursion state */
	struct {
		bool *left_on_path;
	} aug;

	/* Cached count of pairings */
	unsigned int n_matches;
};

struct bim_state *bim_init(void)
{
	struct bim_state *bim;
	unsigned int i;

	bim = talz(NULL, struct bim_state);

	bim->max_left = INIT_STATE_SIZE;
	bim->max_right = INIT_STATE_SIZE;

	bim->left_neigh = tal_arr(bim, unsigned int *, bim->max_left);
	for (i = 0; i < bim->max_left; i++)
		bim->left_neigh[i] = tal_arr(bim, unsigned int, bim->max_right);

	bim->left_neigh_cookie = tal_arr(bim, void **, bim->max_left);
	for (i = 0; i < bim->max_left; i++)
		bim->left_neigh_cookie[i] = tal_arr(bim, void *,
						    bim->max_right);
	bim->n_left_neigh = tal_arrz(bim, unsigned int, bim->max_left);

	bim->left_match = tal_arr(bim, int, bim->max_left);
	memset(bim->left_match, 0xff, bim->max_left * sizeof(int));
	bim->right_match = tal_arr(bim, int, bim->max_right);
	memset(bim->right_match, 0xff, bim->max_right * sizeof(int));

	bim->aug.left_on_path = tal_arr(bim, bool, bim->max_left);

	return bim;
}

void bim_destroy(struct bim_state *bim)
{
	tal_free(bim);
}

static void bim_realloc(struct bim_state *bim,
			unsigned int max_left, unsigned int max_right)
{
	unsigned int i;

	tal_resize(&bim->left_neigh, max_left);
	for (i = 0; i < bim->max_left; i++)
		tal_resize(&bim->left_neigh[i], max_right);
	for (; i < max_left; i++)
		bim->left_neigh[i] = tal_arr(bim, unsigned int, max_right);

	tal_resize(&bim->left_neigh_cookie, max_left);
	for (i = 0; i < bim->max_left; i++)
		tal_resize(&bim->left_neigh_cookie[i], max_right);
	for (; i < max_left; i++)
		bim->left_neigh_cookie[i] = tal_arr(bim, void *, max_right);

	tal_resizez(&bim->n_left_neigh, max_left);

	tal_resize(&bim->left_match, max_left);
	if (max_left > bim->max_left)
		memset(&bim->left_match[bim->max_left], 0xff,
		       (max_left - bim->max_left) * sizeof(int));

	tal_resize(&bim->right_match, max_right);
	if (max_right > bim->max_right)
		memset(&bim->right_match[bim->max_right], 0xff,
		       (max_right - bim->max_right) * sizeof(int));

	tal_resize(&bim->aug.left_on_path, max_left);

	bim->max_left = max_left;
	bim->max_right = max_right;
}

/* Resize the state, can be used both to grow and shrink.
 * Pass 0, 0 to trim overallocation.
 */
void bim_resize(struct bim_state *bim,
		unsigned int max_left, unsigned int max_right)
{
	max_left = max(bim->max_used_left + 1, max_left);
	max_right = max(bim->max_used_right + 1, max_right);

	if (bim->max_left != max_left || bim->max_right != max_right)
		bim_realloc(bim, max_left, max_right);
}

static void bim_size_check(struct bim_state *bim,
			   unsigned int left_id, unsigned int right_id)
{
	bim->max_used_left = max(bim->max_used_left, left_id);
	bim->max_used_right = max(bim->max_used_right, right_id);

	if (bim->max_used_left >= bim->max_left ||
	    bim->max_used_right >= bim->max_right)
		bim_realloc(bim, max(bim->max_used_left * 2, bim->max_left),
			    max(bim->max_used_right * 2, bim->max_right));
}

/* == Algo == */
/* Straightforward implementation of Knuth Max Bipartite Matching */

static void bim_reset_aug_state(struct bim_state *bim)
{
	memset(bim->aug.left_on_path, 0,
	       sizeof(bool) * (bim->max_used_left + 1));
}

static void bim_add_match(struct bim_state *bim,
			  unsigned int left_id, unsigned int right_id)
{
	bim->left_match[left_id] = right_id;
	bim->right_match[right_id] = left_id;
}

static bool bim_try_aug(struct bim_state *bim, unsigned int left_id)
{
	unsigned int i;

	if (bim->aug.left_on_path[left_id])
		return false;
	bim->aug.left_on_path[left_id] = true;

	for (i = 0; i < bim->n_left_neigh[left_id]; i++) {
		unsigned int right_id = bim->left_neigh[left_id][i];

		if (bim->right_match[right_id] == -1 ||
		    bim_try_aug(bim, bim->right_match[right_id])) {
			bim_add_match(bim, left_id, right_id);
			return true;
		}
	}

	return false;
}

/* Ruturns false if edge is a duplicate */
bool bim_add_edge(struct bim_state *bim,
		  unsigned int left_id, unsigned int right_id, void *cookie)
{
	unsigned int i, lv;

	bim_size_check(bim, left_id, right_id);

	/* Add edge */
	for (i = 0; i < bim->n_left_neigh[left_id]; i++)
		/* Duplicate edge add, ignore */
		if (bim->left_neigh[left_id][i] == right_id)
			return false;
	i = bim->n_left_neigh[left_id]++;
	bim->left_neigh[left_id][i] = right_id;
	bim->left_neigh_cookie[left_id][i] = cookie;

	/* Fast path good edge */
	if (bim->left_match[left_id] == -1 &&
	    bim->right_match[right_id] == -1) {
		bim_add_match(bim, left_id, right_id);
		bim->n_matches++;
		return true;
	}

	/* Slow path, re-match */
	for (lv = 0; lv < bim->max_used_left + 1; lv++) {
		if (bim->left_match[lv] != -1)
			continue;
		bim_reset_aug_state(bim);
		if (bim_try_aug(bim, lv)) {
			bim->n_matches++;
			break;
		}
	}

	return true;
}

/* == Accessors == */

unsigned int bim_match_size(struct bim_state *bim)
{
	return bim->n_matches;
}

void bim_walk_init(struct bim_edge *match)
{
	memset(match, 0, sizeof(*match));
}

bool bim_edge_walk_next(struct bim_state *bim, struct bim_edge *match)
{
	unsigned int left_id, i;

	i = match->_walker << 32 >> 32;
	left_id = match->_walker >> 32;
	for (; left_id < bim->max_used_left + 1; left_id++) {
		if (i < bim->n_left_neigh[left_id])
			goto found;
		i = 0;
	}

	return false;

found:
	match->_walker = ((unsigned long long)left_id << 32) | (i + 1);
	match->left_id = left_id;
	match->right_id = bim->left_neigh[left_id][i];
	match->is_match = bim->left_match[left_id] == (int)match->right_id;
	match->cookie = bim->left_neigh_cookie[left_id][i];
	return true;
}

bool bim_match_walk_next(struct bim_state *bim, struct bim_edge *match)
{
	unsigned int left_id, i;

	for (left_id = match->_walker;
	     left_id < bim->max_used_left + 1; left_id++)
		if (bim->left_match[left_id] != -1)
			goto found;
	return false;

found:
	match->is_match = true;
	match->_walker = left_id + 1;
	match->left_id = left_id;
	match->right_id = bim->left_match[left_id];
	match->cookie = NULL;
	for (i = 0; i < bim->n_left_neigh[left_id]; i++)
		if (bim->left_neigh[left_id][i] == match->right_id) {
			match->cookie = bim->left_neigh_cookie[left_id][i];
			break;
		}
	return true;
}

/* == Test / example == */

#ifdef KPERF_UNITS
#include <stdio.h>

static UNNEEDED void bim_dump(struct bim_state *bim)
{
	unsigned int i, j;

	printf("============\n");
	printf("max_l %d max_r %d used_l %d used_r %d matches %d\n",
	       bim->max_left, bim->max_right,
	       bim->max_used_left, bim->max_used_right, bim->n_matches);

	for (i = 0; i <= bim->max_used_left; i++)
		if (bim->left_match[i] != -1)
			printf("  %d -> %d\n", i, bim->left_match[i]);

	for (i = 0; i <= bim->max_used_right; i++)
		if (bim->right_match[i] != -1)
			printf("  %d <- %d\n", i, bim->right_match[i]);

	for (i = 0; i <= bim->max_used_left; i++) {
		if (!bim->n_left_neigh[i])
			continue;

		printf("  =%d=", i);
		for (j = 0; j < bim->n_left_neigh[i]; j++)
			printf(" %d", bim->left_neigh[i][j]);
		printf("\n");
	}
}

int main()
{
	static const int edges[][2] = {{1, 2}, {1, 2}, {2, 2}, {2, 3},
				       {0, 3}, {2, 0}, {170, 18}};
	struct bim_state *bim;
	struct bim_edge m;
	unsigned int i;

	bim = bim_init();
	printf("Init match: %d\n", bim_match_size(bim));

	for (i = 0; i < ARRAY_SIZE(edges); i++) {
		bim_add_edge(bim, edges[i][0], edges[i][1],
			     (void *)(unsigned long)i);
		printf("Added edge %d - %d, match: %d\n",
		       edges[i][0], edges[i][1], bim_match_size(bim));
	}
	bim_for_each_match(bim, &m)
		printf("Match %d - %d, %p\n", m.left_id, m.right_id, m.cookie);

	bim_destroy(bim);
}
#endif
