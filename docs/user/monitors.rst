.. _monitors:

========
Monitors
========

Monitors are components that monitor the target for specific behaviour. A
monitor can be passive and just observe and provide data or behave more actively,
interacting directly with the target. Some monitors also have the capability to
start, stop and restart targets.

Detecting a crash or misbehaviour of your target can be a complex, non-straight
forward process depending on the tools you have available on your targets host;
this holds true especially for embedded devices. Boofuzz provides three main
monitor implementations:

- :class:`ProcessMonitor <boofuzz.monitors.ProcessMonitor>`, a Monitor that collects debug info from process on Windows
  and Unix. It also can restart the target process and detect segfaults.
- :class:`NetworkMonitor <boofuzz.monitors.NetworkMonitor>`, a Monitor that passively captures network traffic via PCAP
  and attaches it to the testcase log.
- :class:`CallbackMonitor <boofuzz.monitors.CallbackMonitor>`, which is used to implement the callbacks that can be
  supplied to the Session class.

Monitor Interface (BaseMonitor)
===============================

.. autoclass:: boofuzz.monitors.BaseMonitor
   :members:
   :undoc-members:
   :show-inheritance:

ProcessMonitor
==============

The process monitor consists of two parts; the ``ProcessMonitor`` class that implements
``BaseMonitor`` and a second module that is to be run on the host of your target.

.. autoclass:: boofuzz.monitors.ProcessMonitor
   :members:
   :undoc-members:

NetworkMonitor
==============

The network monitor consists of two parts; the ``NetworkMonitor`` class that implements
``BaseMonitor`` and a second module that is to be run on a host that can monitor the traffic.

.. autoclass:: boofuzz.monitors.NetworkMonitor
   :members:
   :undoc-members:

CallbackMonitor
===============

.. autoclass:: boofuzz.monitors.CallbackMonitor
   :members:
   :undoc-members:
