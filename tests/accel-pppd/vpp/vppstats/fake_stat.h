/* The fake VPP stats segment of the tests */
#ifndef FAKE_STAT_H
#define FAKE_STAT_H
#include <stdint.h>

struct fake_stat {
	int connect_ok;			/* stat_segment_connect() succeeds */
	void (*on_connect)(void);	/* called inside stat_segment_connect() */
	int stall;			/* the segment is being updated: every wait runs into its timeout */
	uint64_t epoch;			/* the epoch of the segment, VPP bumps it for every interface it creates */
	int hb_frozen;			/* VPP is frozen: the heartbeat stands still */
	int epoch_fail;			/* this many reads report that the directory changed meanwhile */
	int connect_calls, disconnect_calls, access_calls, ls_calls;
};

extern struct fake_stat fake;

/* an empty segment with two threads and FAKE_IFACES interfaces */
#define FAKE_IFACES 64
void fake_reset(void);
/* what VPP counts on an interface, split over the two threads */
void fake_set_counters(uint32_t idx, uint64_t rx_packets, uint64_t rx_bytes, uint64_t tx_packets, uint64_t tx_bytes);

#endif
