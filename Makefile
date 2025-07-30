# SPDX-License-Identifier: BSD-3-Clause

CCAN_PATH := ./ccan
YNL_PATH := ./ynl-c
LIBURING_PATH := ./liburing

CC=gcc
CFLAGS=-std=gnu99   -I$(CCAN_PATH)   -O2   -W -Wall -Wextra -Wno-unused-parameter -Wshadow   -DDEBUG   -g
CFLAGS += -I$(YNL_PATH)/include/
CFLAGS += -I$(LIBURING_PATH)/src/include/

LIBS=-lm -L$(CCAN_PATH) -pthread -lccan
LIBS += -L$(YNL_PATH) -lynl
LIBS += $(LIBURING_PATH)/src/liburing.a

ifdef USE_CUDA
    CFLAGS += -I/usr/local/cuda/include/ -DUSE_CUDA
endif

include $(wildcard *.d)

all: server client units
units: bipartite_match cpu_stat

ifdef USE_CUDA
server: LIBS += -lcuda -lcudart -L/usr/local/cuda/lib64
endif

server: $(CCAN_PATH)/libccan.a $(YNL_PATH)/libynl.a $(LIBURING_PATH)/src/liburing.a server.o server_session.o proto.o epoll.o iou.o worker.o devmem.o cpu_stat.o tcp.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

client: $(CCAN_PATH)/libccan.a client.o proto.o bipartite_match.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(CCAN_PATH)/libccan.a:
	make -C $(CCAN_PATH)/
	ar rcs $(CCAN_PATH)/libccan.a $(CCAN_PATH)/ccan/*/*.o

$(YNL_PATH)/libynl.a:
	make -C $(YNL_PATH)

$(LIBURING_PATH)/src/liburing.a:
	@cd $(LIBURING_PATH) && ./configure --cc=$(CC)
	make -C $(LIBURING_PATH)

clean:
	rm -rf *.o *.d *~ bipartite_match cpu_stat

distclean:
	rm -rf *.o *.d *~ bipartite_match cpu_stat server client $(CCAN_PATH)/libccan.a
	make clean -C $(LIBURING_PATH)

bipartite_match: $(CCAN_PATH)/libccan.a
	$(CC) $(CFLAGS) -DKPERF_UNITS bipartite_match.c -o bipartite_match $(CCAN_PATH)/libccan.a

cpu_stat: $(CCAN_PATH)/libccan.a
	$(CC) $(CFLAGS) -DKPERF_UNITS cpu_stat.c -o cpu_stat $(CCAN_PATH)/libccan.a

%.o: %.c
	$(COMPILE.c) -MMD -o $@ $<

.PHONY: all clean units ccan distclean
.DEFAULT_GOAL=all
