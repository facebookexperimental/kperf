# SPDX-License-Identifier: BSD-3-Clause

CCAN_PATH := ./ccan
YNL_PATH := ./ynl-c

CC=gcc
CFLAGS=-std=gnu99   -I$(CCAN_PATH)  -I$(YNL_PATH)/include/  -O2   -W -Wall -Wextra -Wno-unused-parameter -Wshadow   -DDEBUG   -g

LIBS=-lm -L$(CCAN_PATH) -L$(YNL_PATH) -pthread -lccan -lynl

include $(wildcard *.d)

all: server client units
units: bipartite_match cpu_stat

server: $(CCAN_PATH)/libccan.a $(YNL_PATH)/libynl.a server.o server_session.o proto.o worker.o cpu_stat.o tcp.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

client: $(CCAN_PATH)/libccan.a client.o proto.o bipartite_match.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(CCAN_PATH)/libccan.a:
	make -C $(CCAN_PATH)/
	ar rcs $(CCAN_PATH)/libccan.a $(CCAN_PATH)/ccan/*/*.o

$(YNL_PATH)/libynl.a:
	make -C $(YNL_PATH)

clean:
	rm -rf *.o *.d *~ bipartite_match cpu_stat

distclean:
	rm -rf *.o *.d *~ bipartite_match cpu_stat server client $(CCAN_PATH)/libccan.a

bipartite_match: $(CCAN_PATH)/libccan.a
	$(CC) $(CFLAGS) -DKPERF_UNITS bipartite_match.c -o bipartite_match $(CCAN_PATH)/libccan.a

cpu_stat: $(CCAN_PATH)/libccan.a
	$(CC) $(CFLAGS) -DKPERF_UNITS cpu_stat.c -o cpu_stat $(CCAN_PATH)/libccan.a

%.o: %.c
	$(COMPILE.c) -MMD -o $@ $<

.PHONY: all clean units ccan distclean
.DEFAULT_GOAL=all
