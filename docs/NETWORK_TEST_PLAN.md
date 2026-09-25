# Network qualification plan

## Reference topology

```text
                 Router
               /        \
        Wi-Fi host      Ethernet console
```

This is the primary topology: host and console are on the same LAN but not directly cabled to each other.

## Capture assertions

During a simultaneous game + Discord voice session:

1. Identify console source IP/MAC.
2. Capture at the host ingress/egress.
3. Label Discord destinations learned through the service classifier.
4. Assert that DPI-engine counters increase only for labelled Discord flows.
5. Assert game/PSN/Xbox flows never enter the DPI-engine queue.
6. Compare RTT/throughput against bridge OFF baseline.

## Adverse cases

- host Wi-Fi reconnect
- DHCP lease change
- console IP change
- host sleep/wake
- router reboot
- helper crash
- DPI engine crash
- IPv6 present
- CGNAT WAN
- client/AP isolation
- third-party firewall

Every adverse case must either self-recover or fail closed with a clear UI diagnostic and deterministic rollback.
