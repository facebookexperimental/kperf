/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Jakub Kicinski */
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef BIPARTITE_MATCH
#define BIPARTITE_MATCH

#include <stdbool.h>

struct bim_state;

/**
 * DOC: Bipartite Match
 *
 * Find a matching in a bipartite graph.
 *
 * Number of nodes does not need to be known upfront. Duplicate edges
 * are ignored. Designed for incremental growth of the graph, use
 * bim_match_size() to check number of pairings with current edge set.
 *
 * Example:
 *	struct bim_state *bim;
 *	struct bim_edge m;
 *
 *	bim = bim_init();
 *	while ...
 *		// Add edge to the graph
 *		bim_add_edge(bim, left_id, right_id, priv);
 *
 *	// Dump matches
 *	bim_for_each_match(bim, &m)
 *		printf("Match %d - %d, %p\n", m.left_id, m.right_id, m.cookie);
 *	bim_destroy(bim);
 */

/* Graph init / destroy */
struct bim_state *bim_init(void);
void bim_destroy(struct bim_state *bim);

/* Optional, size the state to avoid reallocation, pass 0s to compact */
void bim_resize(struct bim_state *bim,
		unsigned int max_left, unsigned int max_right);

/* Populating edges */
bool bim_add_edge(struct bim_state *bim,
		  unsigned int left_id, unsigned int right_id, void *cookie);
unsigned int bim_match_size(struct bim_state *bim);

/* Walk pairings and edges */
struct bim_edge {
	unsigned int left_id;
	unsigned int right_id;
	void *cookie;
	bool is_match;
	/* Walker's state, don't overwrite */
	unsigned long long _walker;
};

void bim_walk_init(struct bim_edge *edge);
bool bim_edge_walk_next(struct bim_state *bim, struct bim_edge *edge);
bool bim_match_walk_next(struct bim_state *bim, struct bim_edge *match);

#define bim_for_each_match(bim, match)					\
	for (bim_walk_init(match); bim_match_walk_next(bim, match); )

#define bim_for_each_edge(bim, match)					\
	for (bim_walk_init(match); bim_edge_walk_next(bim, match); )

#endif
