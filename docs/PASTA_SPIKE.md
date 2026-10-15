# Pasta egress spike

Date: 2026-10-13  
Host: `razor`, Ubuntu kernel `7.0.0-38-generic`  
Pasta: Ubuntu `passt` package `0.0~git20260120.386b5f5-1`

## Purpose

Evaluate `pasta` as the egress side of a disposable Saslik network namespace.
The goal is to avoid adding host `FORWARD`, masquerade, bridge or global
forwarding configuration on machines already managed by libvirt/KVM and other
networking applications.

The package was downloaded and extracted under `/tmp`; it was not installed.
All tests used a fresh unprivileged user+network namespace created by pasta.

## Results

| Check | Result | Notes |
| --- | --- | --- |
| Namespace interface | PASS | `saslik-out` configured automatically |
| IPv4 default route | PASS | Supplied by pasta |
| UDP DNS | PASS | Explicit `--dns-forward 169.254.1.1` required |
| IPv4 TCP/HTTPS | PASS | Direct HTTPS reached `1.1.1.1` |
| ICMP echo | PASS | `1.1.1.1` replied |
| IPv6 addressing/routes | PARTIAL | Addresses and default route appeared |
| IPv6 TCP/HTTPS | FAIL | Direct Cloudflare IPv6 connection failed |
| Real Smithproxy process | PASS | Existing `0.9.32` binary ran in the namespace |
| Smithproxy HTTP CONNECT | PASS | CONNECT 200, TLS MITM and HTTP/2 exchange completed |
| Routed ingress veth | PASS | Separate client namespace routed through `saslik-in` |
| Smithproxy TPROXY | PASS | Direct TCP/443 was intercepted on port 50443 |
| Routed Smithproxy egress | PASS | New Smithproxy connection left through `saslik-out`/pasta |
| Host cleanup | PASS | No pasta process, host interface or `ip rule` remained |

The Smithproxy test used the already built Saslik binary and a temporary copy of
its configuration. An HTTPS request through `127.0.0.1:33128` completed through
Smithproxy. Curl observed a certificate issued by `Smithproxy Root CA`, proving
that the request was inspected rather than merely bypassing the proxy.

A second test created a nested client network namespace and this topology:

```text
client0 (10.77.0.2)
    -> saslik-in (10.77.0.1)
    -> TPROXY TCP/443 to Smithproxy :50443
    -> saslik-out
    -> pasta
    -> internet
```

The client used a direct `https://example.com/` request with no HTTP or SOCKS
proxy setting. Curl reported its local address as `10.77.0.2` and observed a
leaf certificate issued by `Smithproxy Root CA`. This proves routed ingress,
transparent interception and pasta egress together. The whole topology lived
inside an unprivileged temporary user namespace, so the test did not alter the
host routing or firewall.

## DNS detail

Razor uses systemd-resolved's loopback stub:

```text
nameserver 127.0.0.53
```

That address refers to the new namespace's loopback and therefore cannot be
used unchanged. Pasta DNS forwarding worked with:

```text
--dns-forward 169.254.1.1
```

Saslik must either provide a namespace-private `resolv.conf` naming that
address or configure Smithproxy and auxiliary services with it explicitly.

## Recommended direction

Use pasta as Saslik's default namespace egress:

```text
host traffic -> saslik-in -> Smithproxy -> saslik-out (pasta) -> host sockets
```

This removes the need for Saslik-owned host forwarding and NAT rules. Host
traffic capture still needs a narrowly scoped output mark and policy-routing
table, but that ruleset should only set Saslik-owned mark bits and issue no
filter verdicts.

Before integration, add focused tests for:

1. host-output policy routing into the real `saslik-in` veth;
2. UDP payloads and QUIC through Smithproxy;
3. Spider and Sift connectivity;
4. private namespace `resolv.conf` handling;
5. the desired IPv6 policy (supported or explicitly blocked);
6. cleanup after SIGINT, SIGTERM and an unclean Saslik exit.
