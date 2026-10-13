---
name: regress
description: Run kperf's regression test (scripts/regress.py) between two hosts - pick a NIC pair, copy a kperf build to the hosts, set the NICs up for devmem, run every mode, and restore the hosts. Use to check kperf changes for regressions, or for baseline throughput, CPU and latency numbers.
---

# kperf regression run

`scripts/regress.py <host1> <if1> <host2> <if2>` runs streams over 4
connections, closed loop RR and open loop RR, each over sockets,
MSG_ZEROCOPY, devmem in both directions and io_uring with zero copy send:
12 runs of a minute, about 13 minutes in all.  host1 sends, host2 receives.
It prints TAP, with each side's rate, busy CPUs (1.00 is one CPU fully
busy) and latencies, and exits with the number of failures.

It only runs the client, on host1.  Copying kperf, setting up the hosts,
the servers and restoring the hosts are up to you, with `scripts/host.py`.

## Pick the hosts and NICs

Both hosts need root access, the same kernel, and NICs with devmem support
(header split, ntuple filters).  Check every candidate NIC on both hosts:

- The PCIe link of the NIC and of every bridge up to the root port runs at
  the full speed and width, a degraded hop caps the throughput:

  ```sh
  d=$(readlink -f /sys/class/net/$IF/device)
  while [ -e $d/current_link_speed ]; do
          echo $(basename $d) $(cat $d/current_link_speed) \
               x$(cat $d/current_link_width)
          d=$(dirname $d)
  done
  ```
- The link is up at full speed, and has a global IPv6 address.
- The interrupt of queue N is on CPU N (`/proc/interrupts`,
  `/proc/irq/*/smp_affinity_list`), on the NIC's NUMA node.  regress.py
  runs each worker 4 CPUs above the interrupt of its flow (`--pin-off 4`).

## Copy kperf

Build with `make`, then copy `server`, `client` and `scripts/host.py` to a
new directory on both hosts, as `kperf-server` and `kperf-client`:

```sh
D=/tmp/kperf-regress-$(date +%Y%m%d-%H%M%S)
ssh root@$H "mkdir -p $D"
scp server root@$H:$D/kperf-server
scp client root@$H:$D/kperf-client
scp skills/regress/scripts/host.py root@$H:$D/
```

Both hosts need the same build, the protocol checks it.  kperf names
itself after its binary in its output (`kperf-client: ...`).

## Run

On each host, with the local and the peer's address on the NIC:

```sh
ssh root@$H1 "$D/host.py setup $IF1 $ADDR1 $ADDR2"
ssh root@$H2 "$D/host.py setup $IF2 $ADDR2 $ADDR1"
ssh root@$H1 "$D/host.py start"
ssh root@$H2 "$D/host.py start"
KPERF_CLIENT=$D/kperf-client skills/regress/scripts/regress.py \
        $H1 $IF1 $H2 $IF2 | tee regress.tap
ssh root@$H1 "$D/host.py restore"                   # must print restored
ssh root@$H2 "$D/host.py restore"
```

setup and start fail with a traceback when the NIC can't do what the run
needs.  Restore even when the run fails or gets interrupted, and check that
it prints `restored`, else it lists what differs from before setup.
`restore` can be run again.

If ssh needs another transport (asks for a password, or there is a
wrapper), set `SSH`, e.g. `SSH=sush2`, and use it for the host commands
too (`suscp` instead of scp).  regress.py passes it ssh options
(`-o BatchMode=yes`) and the command as one argument, with stdin from
/dev/null.  Quote remote commands as one argument too: sush2 parses the
options of the command (`mkdir -p`) as its own.  Don't put a wrapper
called `ssh` first in `PATH`: transports which run ssh themselves would
recurse into it.

## Gotchas

`host.py` handles these, they matter when something fails:

- udmabuf allocations are capped by `size_limit_mb` of the udmabuf module,
  64MB by default.  The streams use 2GB dma-bufs: setup raises it to 2048.
- devmem RX needs header split (`ethtool -G tcp-data-split on`), and on
  mlx5 header split needs hardware GRO (`rx-gro-hw`).  mlx5 won't turn GRO
  off while splitting headers: restore turns header split off first.
- devmem RX needs `hds-thresh` 0, some NICs default to more (fbnic 1536).
- Hosts may route the peer through another NIC; devmem only sees the
  traffic of its NIC.  setup adds a /128 route through the NIC's gateway.
- kperf resets the RSS table with the legacy ioctl, which turns symmetric
  hashing (`symmetric-or-xor`) off on mlx5.  restore turns it back on.
- A session which dies (a crash, a failed setup, a kill) leaves its ntuple
  rules, RSS contexts and a changed default RSS table behind.  restore
  removes those which weren't there before.  Stop servers only once their
  sessions are gone, which restore waits for.
- The devmem RX dma-buf is shared by the queues of the test, 128MB is
  enough for one: with 4 queues and less memory, connections stall.
- Hosts get rebooted into other kernels: check `uname -r` before a run.
- `--rx-page-size` above 4K needs hugepages, DCTCP needs
  `net.ipv4.tcp_ecn=1` or falls back to Reno.  regress.py uses neither.
- io_uring zero copy receive is not part of the run, it does not work on
  mlx5 yet.

## Read the results

Every run should be `ok`.  A `not ok` line is followed by the client's
command and output.  Compare against a previous run between the same
hosts and NICs:

- Stream rates are each side's sum over the connections.  The streams
  other than devmem discard on receive (`--msg-trunc`).  On 400G mlx5,
  the streams which don't copy on send reach line rate (about 389 Gbps),
  the socket stream is limited by the sender copying.
- Closed loop RR on mlx5 does about 20-25k requests per second, at p50
  of about 36us.  Open loop sends 10k requests per second.
- `max` and the open loop tail percentiles show stalls of the hosts
  themselves; some hosts stall for about 67ms periodically.
