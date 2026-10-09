# Scoped HTTP metadata observer

`bin/kb-http` builds and loads a passive yeet TCX ingress probe on loopback interface 1. It observes only TCP traffic with source or destination port 8899, the local daemon credential-execution endpoint.

The kernel copies at most 95 first-line bytes into a zeroed event and stops at CR or LF. Headers and bodies never enter the event. The yeet loader emits method, path without query parameters, response status, ports, and a monotonic timestamp. Request and response events are separate; pairing and wall-clock correlation belong to the daemon.

This is local plaintext HTTP metadata, not inspection of upstream encrypted HTTPS or every agent syscall. Split first lines, long lines, IPv6 extension headers, and non-HTTP traffic may be omitted. It is a passive observer; the separate LSM guard enforces access.

IPv4/IPv6 TCP parsing adapted from the GPL-2.0 public `yeet-src/httpinspect` BPF example. No yeet Rust source is included or modified.
