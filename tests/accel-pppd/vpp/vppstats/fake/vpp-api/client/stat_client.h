/*
 * The part of the VPP stats client API that vppstats.c uses, for tests without
 * VPP. The functions are in fake_stat_client.c and work on a segment the test
 * builds.
 */
#ifndef FAKE_STAT_CLIENT_H
#define FAKE_STAT_CLIENT_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
	uint64_t packets, bytes;
} vlib_counter_t;

typedef enum {
	STAT_DIR_TYPE_ILLEGAL = 0,
	STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED = 5,
} stat_directory_type_t;

typedef struct {
	char *name;
	stat_directory_type_t type;
	void *data;
} vlib_stats_entry_t;

typedef struct {
	uint64_t epoch;
} stat_segment_access_t;

typedef struct {
	vlib_stats_entry_t *directory_vector;
	uint64_t current_epoch;
	uint64_t timeout;
} stat_client_main_t;

extern stat_client_main_t stat_client_main;

int stat_segment_connect(const char *socket_name);
void stat_segment_disconnect(void);
int stat_segment_vec_len(void *vec);
uint32_t *stat_segment_ls(uint8_t **pattern);
int stat_segment_access_start(stat_segment_access_t *sa, stat_client_main_t *sm);
bool stat_segment_access_end(stat_segment_access_t *sa, stat_client_main_t *sm);
void *stat_segment_adjust(stat_client_main_t *sm, void *data);
double stat_segment_heartbeat(void);
void stat_segment_set_timeout(uint64_t timeout);

#endif
