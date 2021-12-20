.. SPDX-License-Identifier: BSD-3-Clause

kperf
=====

kperf is a an iperf/netperf replacement with a more fine-grained worker
control. Modern NICs have multiple Rx queues and while iperf / netperf
can bind to a CPU they are not aware of which CPU is serving the Rx queue
selected by the NIC for the flow. If the NIC does not support flow steering
this is a problem. kperf asks the kernel which CPU is used for Rx and can
bind itself appropriately (same core, Rx core + N, etc.). For parallel runs
it can also make sure that the flows are not colliding (being served by
the same CPU).

Other strengths include:
 - RPC-like traffic (unlike iperf);
 - kTLS support (just data, no control records);
 - more stats (TCP, latency, CPU use).

That said, kperf is more of hackable library than a ready-to-use Swiss
army knife. There is an example client application provided but the number
of configurations is so high it seems impossible to write a comprehensive
client controlled solely by command line options.

High level design
-----------------

Client does not generate any traffic, it only orchestrates load between
Servers.

When Client connect to a Server Server spawns a Session which is what
Client controls on the server side. There can be multiple concurrent
Sessions within one Server, there are no limitations. Note that Session
is between Client and one Server, it can contain connections to many
other Sessions. Each Session is a separate process.

Session can establish Connections with other Sessions.

Session can spawn Workers which is what drivers the IO.

Connections are established within Sessions, not Workers because Workers
and Connections are usually assigned once it's known which CPU given
connection lands on.

Currently only Process Workers are supported (each worker is a separate
process), adding threads should not be a problem but was not needed, so far::

                                  .--------.
                            .-----| Client |----.
                            |     '--------'    |
                            |                   |
      ----------------------|------       ------|---------------------
                            v      |     |      v
        .--------.     .---------. |     | .---------.     .--------.
        | Server |-----| Session | |     | | Session |-----| Server |
        '--------'     '---------' |     | '---------'     '--------'
                            |      |     |      |
                            v      |     |      v
                       .---------. |     | .---------.
                       | Worker  | |     | | Worker  |
                       '---------' |     | '---------'
     Host A            .---------. |     | .---------.        Host B
                       | Worker  | |     | | Worker  |
                       '---------' |     | '---------'
                       .---------. |     | .---------.
                       | Worker  | |     | | Worker  |
                       '---------' |     | '---------'
                                   |     |

Contributing
------------

Please refer to relevant details in the `license`_, `code of conduct`_,
and `contributing guide`_.

.. _license: LICENSE
.. _code of conduct: CODE_OF_CONDUCT.md
.. _contributing guide: CONTRIBUTING.md

Per Meta's policies contributors are required to submit a CLA.
