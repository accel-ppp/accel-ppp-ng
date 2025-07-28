/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * rt_names.c		rtnetlink names DB.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <dirent.h>
#include <limits.h>

#include <asm/types.h>
#include <linux/rtnetlink.h>

#include "rt_names.h"
#include "utils.h"

#include "triton.h"

#define NAME_MAX_LEN 512
#define CONFDIR "/etc/iproute2"

struct rtnl_hash_entry {
	struct rtnl_hash_entry	*next;
	const char		*name;
	unsigned int		id;
};

static int fread_id_name(FILE *fp, int *id, char *namebuf)
{
	char buf[NAME_MAX_LEN];

	while (fgets(buf, sizeof(buf), fp)) {
		char *p = buf;

		while (*p == ' ' || *p == '\t')
			p++;

		if (*p == '#' || *p == '\n' || *p == 0)
			continue;

		/* TODO: Better/safer scanning method required? Maybe regex?*/
		/* 511 is NAME_MAX_LEN - 1 */
		if (sscanf(p, "0x%x %511s\n", id, namebuf) != 2 &&
				sscanf(p, "0x%x %511s #", id, namebuf) != 2 &&
				sscanf(p, "%d %511s\n", id, namebuf) != 2 &&
				sscanf(p, "%d %511s #", id, namebuf) != 2) {
			strncpy(namebuf, p, NAME_MAX_LEN -1);
			namebuf[NAME_MAX_LEN - 1] = 0;
			return -1;
		}
		return 1;
	}
	return 0;
}

static int
rtnl_hash_initialize(const char *file, struct rtnl_hash_entry **hash, int size)
{
	struct rtnl_hash_entry *entry;
	FILE *fp;
	int id;
	char namebuf[NAME_MAX_LEN] = {0};
	int ret = 0;

	fp = fopen(file, "r");
	if (!fp)
		return -1;

	while ((ret = fread_id_name(fp, &id, &namebuf[0]))) {
		if (ret == -1) {
			fprintf(stderr, "Database %s is corrupted at %s\n",
					file, namebuf);
			break;
		}

		if (id < 0)
			continue;

		entry = malloc(sizeof(*entry));
		if (entry == NULL) {
			fprintf(stderr, "malloc error: for entry\n");
			ret = -1;
			break;
		}
		entry->id   = id;
		entry->name = strdup(namebuf);
		entry->next = hash[id & (size - 1)];
		hash[id & (size - 1)] = entry;
	}
	fclose(fp);

	return ret;
}

static struct rtnl_hash_entry dflt_table_entry  = { .name = "default" };
static struct rtnl_hash_entry main_table_entry  = { .name = "main" };
static struct rtnl_hash_entry local_table_entry = { .name = "local" };

static struct rtnl_hash_entry *rtnl_rttable_hash[256] = {
	[RT_TABLE_DEFAULT] = &dflt_table_entry,
	[RT_TABLE_MAIN]    = &main_table_entry,
	[RT_TABLE_LOCAL]   = &local_table_entry,
};

static int rtnl_rttable_init;

static void rtnl_rttable_initialize(void)
{
	struct dirent *de;
	DIR *d;
	int i;
	int ret = 0;

	rtnl_rttable_init = 1;
	for (i = 0; i < 256; i++) {
		if (rtnl_rttable_hash[i])
			rtnl_rttable_hash[i]->id = i;
	}
	ret = rtnl_hash_initialize(CONFDIR "/rt_tables",
			     rtnl_rttable_hash, 256);
	if (ret) {
		fprintf(stderr, "Issue while initializing rtnl hash from rt_tables\n");
		return;
	}

	d = opendir(CONFDIR "/rt_tables.d");
	if (!d)
		return;

	while ((de = readdir(d)) != NULL) {
		char path[PATH_MAX];
		size_t len;

		if (*de->d_name == '.')
			continue;

		/* only consider filenames ending in '.conf' */
		len = strnlen(de->d_name, PATH_MAX - 1);
		if (len <= 5)
			continue;
		if (strncmp(de->d_name + len - 5, ".conf", 6))
			continue;

		snprintf(path, sizeof(path),
			 CONFDIR "/rt_tables.d/%s", de->d_name);
		ret = rtnl_hash_initialize(path, rtnl_rttable_hash, 256);
		if (ret) {
			fprintf(stderr, "Issue while initializing rtnl hash from file \'%s\' - skip the file\n", path);
		}
	}
	closedir(d);
}

int rtnl_rttable_a2n(uint32_t *id, const char *arg)
{
	static const char *cache;
	static unsigned long res;
	struct rtnl_hash_entry *entry;
	char *end;
	unsigned long i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rttable_init)
		rtnl_rttable_initialize();

	for (i = 0; i < 256; i++) {
		entry = rtnl_rttable_hash[i];
		while (entry && strcmp(entry->name, arg))
			entry = entry->next;
		if (entry) {
			cache = entry->name;
			res = entry->id;
			*id = res;
			return 0;
		}
	}

	i = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || i > RT_TABLE_MAX)
		return -1;
	*id = i;
	return 0;
}

/* accel-pppd startup init routine */
static void rt_names_init(void)
{
	rtnl_rttable_initialize();
}

static void __exit rt_names_exit(void)
{
	int i = 0;

	if (!rtnl_rttable_init)
		return;

	for (i = 0; i < 256; ++i) {
		struct rtnl_hash_entry *entry = rtnl_rttable_hash[i];

		while (entry) {
			struct rtnl_hash_entry *e = entry;
			entry = entry->next;
			free(e);
		}
	}
}

DEFINE_INIT(1, rt_names_init);