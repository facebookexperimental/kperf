#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright Meta Platforms, Inc. and affiliates

"""
Run kperf between two hosts with streams over 4 connections, closed loop
and open loop RR, each over sockets, MSG_ZEROCOPY, devmem in both
directions and io_uring with zero copy send, for a minute each.  Reports
the runs in TAP, with the rate, the busy CPUs and the latencies of each
side, and exits with the number of failures.

host1 sends and host2 receives.  The client runs on host1 as root, through
the ssh command in $SSH (default ssh), as $KPERF_CLIENT (default
kperf-client).  kperf servers must be running on both hosts, and both NICs
must be set up for devmem, see ../SKILL.md.
"""

import json
import os
import re
import shlex
import subprocess
import sys

STREAM = ['--num-connections', '4', '--num-rx-queues', '4',
          '--dmabuf-rx-size-mb', '2048', '--dmabuf-tx-size-mb', '2048',
          '--read-size', '67108864', '--write-size', '67108864']
RR = ['-s', '4096', '--resp-size', '4096', '-T', '2', '--warmup', '100']
OPEN_LOOP = RR + ['--rps', '10000']
DEVMEM = ['--devmem-rx', '--devmem-tx']
IOU = ['--iou-src', '--iou-dst', '--msg-zerocopy']
RUNS = {
    'stream socket': STREAM + ['--msg-trunc'],
    'stream zerocopy': STREAM + ['--msg-zerocopy', '--msg-trunc'],
    'stream devmem': STREAM + DEVMEM,
    'stream io_uring': STREAM + IOU + ['--msg-trunc'],
    'rr socket': RR,
    'rr zerocopy': RR + ['--msg-zerocopy'],
    'rr devmem': RR + DEVMEM,
    'rr io_uring': RR + IOU,
    'open-loop socket': OPEN_LOOP,
    'open-loop zerocopy': OPEN_LOOP + ['--msg-zerocopy'],
    'open-loop devmem': OPEN_LOOP + DEVMEM,
    'open-loop io_uring': OPEN_LOOP + IOU,
}
CPU_FIELDS = ('usr', 'sys', 'idle', 'iow', 'irq', 'sirq')
SSH = shlex.split(os.environ.get('SSH', 'ssh'))
CLIENT = os.environ.get('KPERF_CLIENT', 'kperf-client')
TIME = 60

ERROR_RE = re.compile(r'rror|ailed|died|No result|Invalid|zero send|'
                      r'not supported')
SIDE_RE = re.compile(r'== (Source|Target)')
RATE_RE = re.compile(r' (Tx|Rx) *([\d.]+) Gbps')
RPS_RE = re.compile(r': ([\d.]+) RPS(?: \(target (\d+))?')
LAT_RE = re.compile(r': (p25:.*)$')
CPU_RE = re.compile(r'CPU\s*(\d+):' +
                    ''.join(rf' {f}:\s*([\d.]+)%' for f in CPU_FIELDS))


def ssh(host, cmd, timeout):
    return subprocess.run([*SSH, '-o', 'BatchMode=yes',
                           '-o', 'LogLevel=ERROR', f'root@{host}', cmd],
                          stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=timeout, check=False)


def address(host, ifname):
    res = ssh(host, f'ip -j -6 addr show dev {ifname} scope global', 30)
    # ip leaves an empty entry for each address of another scope
    return next(a['local'] for a in json.loads(res.stdout)[0]['addr_info']
                if 'local' in a)


def parse(log):
    """Split the client's output into the results of the source and target"""
    sides = {}
    side = None
    for line in log.splitlines():
        m = SIDE_RE.search(line)
        if m:
            side = sides.setdefault(m[1].lower(), {
                'Tx': [], 'Rx': [], 'rps': None, 'target': None, 'cpu': {},
                'lat': None,
            })
            continue
        if side is None:
            continue
        m = RATE_RE.search(line)
        if m:
            side[m[1]].append(float(m[2]))
            continue
        m = RPS_RE.search(line)
        if m:
            side['rps'] = float(m[1])
            side['target'] = int(m[2]) if m[2] else None
            continue
        m = LAT_RE.search(line)
        if m:
            side['lat'] = m[1]
            continue
        m = CPU_RE.search(line)
        if m:
            # Count each CPU once, it may show up for both the net and app
            side['cpu'].setdefault(int(m[1]),
                                   dict(zip(CPU_FIELDS,
                                            map(float, m.groups()[1:]))))
    return sides


def check(test, rc, log, sides):
    """Return why a run failed, or None.  The client's exit status isn't
    enough: it exits 0 when a test fails to start."""
    m = ERROR_RE.search(log)
    if m:
        return log[log.rfind('\n', 0, m.start()) + 1:].split('\n', 1)[0]
    if rc:
        return f'client exited with {rc}'
    if 'source' not in sides or 'target' not in sides:
        return 'no results'

    src, dst = sides['source'], sides['target']
    if test == 'stream':
        if len(dst['Rx']) != 4 or not all(dst['Rx']):
            return 'not all connections received data'
        return None
    if not src['rps'] or not dst['rps']:
        return 'no RPS from both sides'
    if src['target'] and src['rps'] < 0.9 * src['target']:
        return 'below 90% of the target rate'
    return None


def stats(test, sides):
    """Lines with the rate of each side, its CPUs busy, summed over the
    CPUs of its workers and of their flows' interrupts, and its latencies"""
    lines = []
    for name in ('source', 'target'):
        side = sides.get(name)
        if not side or not side['cpu']:
            continue
        if test == 'stream':
            rate = f"{sum(side['Tx' if name == 'source' else 'Rx']):.2f} Gbps"
        else:
            rate = f"{side['rps'] or 0:.1f} RPS"
        cpus = {f: sum(c[f] for c in side['cpu'].values()) / 100
                for f in ('usr', 'sys', 'irq', 'sirq')}
        split = ' '.join(f'{v:.2f} {f}' for f, v in cpus.items())
        lines.append(f'{name}: {rate}, {sum(cpus.values()):.2f} CPUs '
                     f'({split})')
        if side['lat']:
            lines.append(f"{name}: {side['lat']}")
    return lines


def main():
    if len(sys.argv) != 5:
        sys.exit(f'usage: {sys.argv[0]} <host1> <if1> <host2> <if2>')
    host1, if1, host2, if2 = sys.argv[1:]
    src = address(host1, if1)
    dst = address(host2, if2)

    print(f'1..{len(RUNS)}')
    print(f'# {host1} {if1} {src} -> {host2} {if2} {dst}')
    fails = 0
    for n, (name, args) in enumerate(RUNS.items(), 1):
        test = name.split()[0]
        cmd = [CLIENT, '--src', src, '--dst', dst,
               '--validate', 'no', '-t', str(TIME), '--pin-off', '4', *args]
        res = ssh(host1, shlex.join(cmd), TIME + 120)
        log = res.stdout + res.stderr
        sides = parse(log)
        why = check(test, res.returncode, log, sides)

        if why:
            fails += 1
            print(f'not ok {n} - {name}: {why}')
            print(f'# {shlex.join(cmd)}')
            for line in log.splitlines():
                print(f'# {line}')
        else:
            print(f'ok {n} - {name}')
        for line in stats(test, sides):
            print(f'#   {line}')
        sys.stdout.flush()

    sys.exit(fails)


if __name__ == '__main__':
    main()
