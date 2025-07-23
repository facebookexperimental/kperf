// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include <stdio.h>
#include <linux/tcp.h>

#include "tcp.h"

void print_tcp_info(struct tcp_info *ti)
{
	printf("TCP stats\n"
	       "         %u %u %u %u %u %u %u %u %u %u\n"
	       "         %u %u %u %u %u %u %u %u %u\n"
	       "Times:   %u %u %u %u\n"
	       "Metrics: %u %u %u %u %u %u %u %u\n"
	       "rcv_rtt| %u %u %u\n"
	       "pacing_| %llu %llu %llu %llu\n"
	       "segs_ou| %u %u %u %u %u %u\n"
	       "de-ry_r| %llu %llu %llu %llu\n"
	       "de-ered| %u %u\n"
	       "bytes_s| %llu %llu\n"
	       "dsack_d| %u %u %u %u\n",
	       ti->tcpi_state,
	       ti->tcpi_ca_state,
	       ti->tcpi_retransmits,
	       ti->tcpi_probes,
	       ti->tcpi_backoff,
	       ti->tcpi_options,
	       ti->tcpi_snd_wscale,
	       ti->tcpi_rcv_wscale,
	       ti->tcpi_delivery_rate_app_limited,
	       ti->tcpi_fastopen_client_fail,

	       ti->tcpi_rto,
	       ti->tcpi_ato,
	       ti->tcpi_snd_mss,
	       ti->tcpi_rcv_mss,

	       ti->tcpi_unacked,
	       ti->tcpi_sacked,
	       ti->tcpi_lost,
	       ti->tcpi_retrans,
	       ti->tcpi_fackets,

	       /* Times. */
	       ti->tcpi_last_data_sent,
	       ti->tcpi_last_ack_sent,
	       ti->tcpi_last_data_recv,
	       ti->tcpi_last_ack_recv,

	       /* Metrics. */
	       ti->tcpi_pmtu,
	       ti->tcpi_rcv_ssthresh,
	       ti->tcpi_rtt,
	       ti->tcpi_rttvar,
	       ti->tcpi_snd_ssthresh,
	       ti->tcpi_snd_cwnd,
	       ti->tcpi_advmss,
	       ti->tcpi_reordering,

	       ti->tcpi_rcv_rtt,
	       ti->tcpi_rcv_space,

	       ti->tcpi_total_retrans,

	       ti->tcpi_pacing_rate,
	       ti->tcpi_max_pacing_rate,
	       ti->tcpi_bytes_acked,	/* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	       ti->tcpi_bytes_received,	/* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	       ti->tcpi_segs_out,	/* RFC4898 tcpEStatsPerfSegsOut */
	       ti->tcpi_segs_in,	/* RFC4898 tcpEStatsPerfSegsIn */

	       ti->tcpi_notsent_bytes,
	       ti->tcpi_min_rtt,
	       ti->tcpi_data_segs_in,	/* RFC4898 tcpEStatsDataSegsIn */
	       ti->tcpi_data_segs_out,	/* RFC4898 tcpEStatsDataSegsOut */

	       ti->tcpi_delivery_rate,

	       ti->tcpi_busy_time,	/* Time (usec) busy sending data */
	       ti->tcpi_rwnd_limited,	/* Time (usec) limited by receive window */
	       ti->tcpi_sndbuf_limited,	/* Time (usec) limited by send buffer */

	       ti->tcpi_delivered,
	       ti->tcpi_delivered_ce,

	       ti->tcpi_bytes_sent,	/* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	       ti->tcpi_bytes_retrans,	/* RFC4898 tcpEStatsPerfOctetsRetrans */
	       ti->tcpi_dsack_dups,	/* RFC4898 tcpEStatsStackDSACKDups */
	       ti->tcpi_reord_seen,	/* reordering events seen */

	       ti->tcpi_rcv_ooopack,	/* Out-of-order packets received */

	       ti->tcpi_snd_wnd		/* peer's advertised receive window
					 * after scaling (bytes) */
		);
}
