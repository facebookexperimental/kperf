#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright Meta Platforms, Inc. and affiliates

"""
The host side of a kperf regression run, see ../SKILL.md.  Run as root, next
to kperf-server.  It keeps the state of the run in its directory:

  host.py setup <nic> <local addr> <peer addr>
  host.py start
  host.py restore

setup saves the state of the NIC, then sets it up for devmem.  restore
stops the server, undoes setup and what a dead session left behind, and
compares the NIC with the saved state.
"""

import json
import os
import re
import signal
import subprocess
import sys
import time

UDMABUF = '/sys/module/udmabuf/parameters/size_limit_mb'
PORT = 18323


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True,
                          text=True).stdout


def val(text, key):
    return re.findall(rf'^\s*{key}:\s*(\S+)', text, re.M)[-1]


def table(rss):
    return re.findall(r'^\s+\d+:.*$', rss, re.M)


def contexts(nic):
    return [c for c in range(1, 33)
            if not os.system(f'ethtool -x {nic} context {c} >/dev/null 2>&1')]


def state(nic, peer):
    return {
        'features': sh(f'ethtool -k {nic}'),
        'ring': sh(f'ethtool -g {nic}'),
        'rss': sh(f'ethtool -x {nic}'),
        'ntuple': sh(f'ethtool -n {nic}'),
        'contexts': contexts(nic),
        'route': sh(f'ip -6 route show {peer}/128'),
        'udmabuf': open(UDMABUF).read(),
    }


def setup(nic, local, peer):
    with open('state.json', 'w') as f:
        json.dump({'nic': nic, 'local': local, 'peer': peer,
                   'state': state(nic, peer)}, f)

    # mlx5 splits headers only with hardware GRO
    sh(f'ethtool -K {nic} rx-gro-hw on')
    sh(f'ethtool -G {nic} tcp-data-split on')
    # devmem needs all headers split, some NICs keep short packets whole
    if val(sh(f'ethtool -g {nic}'), 'HDS thresh').isdigit():
        sh(f'ethtool -G {nic} hds-thresh 0')
    sh(f'ethtool -K {nic} ntuple on')
    # The streams use 2GB dma-bufs, the limit defaults to 64MB
    with open(UDMABUF, 'w') as f:
        f.write('2048')
    # devmem only sees the traffic of its NIC
    if f'dev {nic} ' not in sh(f'ip -6 route get {peer}'):
        route = sh(f'ip -6 route get {peer} from {local}')
        gw = re.search(r'via (\S+)', route)[1]
        sh(f'ip -6 route add {peer}/128 via {gw} dev {nic} src {local}')

    assert val(sh(f'ethtool -g {nic}'), 'TCP data split') == 'on'
    assert val(sh(f'ethtool -k {nic}'), 'ntuple-filters') == 'on'
    subprocess.run(f'ping -q -c 2 -I {local} {peer}', shell=True, check=True)


def start():
    run = json.load(open('state.json'))
    server = subprocess.Popen(['./kperf-server', '-a', run['local'],
                               '-p', str(PORT), '--no-daemon'],
                              stdout=open('server.log', 'w'),
                              stderr=subprocess.STDOUT,
                              stdin=subprocess.DEVNULL,
                              start_new_session=True)
    with open('server.pid', 'w') as f:
        f.write(str(server.pid))
    time.sleep(2)
    assert 'Bound to' in open('server.log').read()


# A session killed with the server skips its teardown, and leaves its RX
# steering behind: wait for the sessions to finish first.
def stop():
    pid = int(open('server.pid').read())
    os.remove('server.pid')
    while sh(f'pgrep -P {pid}'):
        time.sleep(0.25)
    os.kill(pid, signal.SIGTERM)
    while not os.system(f'kill -0 {pid} 2>/dev/null'):
        time.sleep(0.25)


def restore():
    run = json.load(open('state.json'))
    nic, peer, saved = run['nic'], run['peer'], run['state']
    if os.path.exists('server.pid'):
        stop()
    if not saved['route']:
        sh(f'ip -6 route del {peer}/128')

    # What a dead session left behind: ntuple rules, RSS contexts, and the
    # default RSS context moved off the queues of the test
    if 'Total 0 rules' in saved['ntuple']:
        for r in re.findall(r'^Filter: (\d+)', sh(f'ethtool -n {nic}'), re.M):
            sh(f'ethtool -N {nic} delete {r}')
    for c in set(contexts(nic)) - set(saved['contexts']):
        sh(f'ethtool -X {nic} context {c} delete')
    if table(sh(f'ethtool -x {nic}')) != table(saved['rss']):
        sh(f'ethtool -X {nic} default')

    # mlx5 won't turn hardware GRO off while it splits headers
    hds = val(saved['ring'], 'TCP data split').replace('n/a', 'auto')
    gro = val(saved['features'], 'rx-gro-hw')
    ntuple = val(saved['features'], 'ntuple-filters')
    sh(f'ethtool -G {nic} tcp-data-split off')
    sh(f'ethtool -K {nic} rx-gro-hw {gro} ntuple {ntuple}')
    sh(f'ethtool -G {nic} tcp-data-split {hds}')
    if val(saved['ring'], 'HDS thresh').isdigit():
        sh(f'ethtool -G {nic} hds-thresh {val(saved["ring"], "HDS thresh")}')

    # Resetting the RSS table through the legacy ioctl, as kperf does, turns
    # symmetric hashing off
    for x in ('symmetric-xor', 'symmetric-or-xor'):
        if f'{x}: on' in saved['rss'] and \
           f'{x}: off' in sh(f'ethtool -x {nic}'):
            sh(f'ethtool -X {nic} xfrm {x}')
    with open(UDMABUF, 'w') as f:
        f.write(saved['udmabuf'])

    now = state(nic, peer)
    differs = [k for k in saved if now[k] != saved[k]]
    print(f'differs: {" ".join(differs)}' if differs else 'restored')
    sys.exit(len(differs))


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    {'setup': setup, 'start': start, 'restore': restore}[sys.argv[1]](
        *sys.argv[2:])
