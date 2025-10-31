#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright Meta Platforms, Inc. and affiliates

"""
Script to run kperf.
This needs to be copied into kernel selftest directory to run.
It depends on kernel networking selftest infra and libraries.
"""

import time
import psutil
from lib.py import ksft_run, ksft_exit
from lib.py import NetDrvEpEnv
from lib.py import bkg, cmd


def kperf(cfg):
    """ Run a bunch of kperf configs. Checking is expected to be manual. """
    kpdr = "/home/kicinski/devel/kperf/"
    s1 = bkg(kpdr + "server --no-daemon")
    s2 = bkg(kpdr + "server --no-daemon --pid-file /tmp/kperf-remote.pid",
             host=cfg.remote)

    time.sleep(0.3)

    fd_cnt = psutil.Process(s1.proc.pid).num_fds()
    print("Server fd count at the start:", fd_cnt)

    print(">>> Base run")
    run = cmd(kpdr + f"client --src {cfg.addr} --dst {cfg.remote_addr} -t 10",
              fail=False)
    if run.stderr:
        print("STDERR:", run.stderr)
    print(run.stdout)

    print(">>> pin-off 1")
    run = cmd(kpdr + f"client --cpu-max 2 --src {cfg.addr} --dst {cfg.remote_addr} --pin-off 1 -t 10",
              fail=False)
    if run.stderr:
        print("STDERR:", run.stderr)
    print(run.stdout)

    end_fd_cnt = psutil.Process(s1.proc.pid).num_fds()
    print("Server fd count at the end:", end_fd_cnt)
    if end_fd_cnt != fd_cnt:
        print(f"ERROR!!! (was {fd_cnt} at init)")
        print(cmd("lsof -p " + str(s1.proc.pid)).stdout)

    s1.process(terminate=True, fail=False)
    s2.process(terminate=True, fail=False)

    print(s1.stderr, s1.stdout)
    print(s2.stderr, s2.stdout)



def main() -> None:
    """ Ksft boiler plate main """

    with NetDrvEpEnv(__file__) as cfg:
        ksft_run([kperf],
                 args=(cfg, ))
    ksft_exit()


if __name__ == "__main__":
    main()
