# BACSE203 — Computer Networks: Project Report
## Topic 2: Userspace IP Router / Software Switch

### Implemented Features
- RFC 1071 packet-header and ICMP checksum calculation and validation.
- Simulated ICMP Echo Request and Echo Reply.
- ICMP Time Exceeded response when TTL is 1.
- ICMP Destination Unreachable response when ARP resolution fails or times out.
- Dynamic ARP request broadcasting, reply caching, cache aging, and pending-packet queueing.
- UDP-based test client for injecting packets and checking forwarded and ICMP responses.

### Basic Details

* **Project Title:** Userspace IP Router & Software Switch with Dynamic ARP, LPM Trie Routing, and ICMP Control Plane
* **Course Code:** BACSE203 — Computer Networks
* **GitHub Repository:** [https://github.com/tvesha09/cn_project](https://github.com/tvesha09/cn_project)
* **Programming Language & Tools:** C (C99), POSIX Sockets, Pthreads, Wireshark, GCC, Make, Git

#### Team Members & Contribution Split

| Team Member | Registration No. | Assigned Role & Modules | Core Contributions |
| :--- | :--- | :--- | :--- |
| **Ananya Alshi** | 25BCE0981 | **Member 1:** Link-Layer & Dynamic ARP Engine | Dynamic ARP request broadcasting, ARP reply parsing, ARP cache table management, timestamp-based entry expiration/eviction, and packet queuing during address resolution (`src/arp.c`, `include/arp.h`). |
| **Tvesha Rathi** | 25BCE2001 | **Member 2:** Routing Optimization, LPM & Data Plane Integrity | Binary Prefix Trie for $O(32)$ Longest Prefix Match (LPM) lookups, RFC 1071 one's complement Internet checksum calculation & incremental recalculation on TTL decrement, IPv4 header validation, and quantitative scaling benchmark suite (`src/lpm.c`, `src/checksum.c`, `test/benchmark_lpm.c`). |
| **Saanvi Kukreja** | 25BDS0134 | **Member 3:** Integration, ICMP Engine & Verification | Forwarding pipeline integration, ICMP control plane (Echo Reply Type 0, Time Exceeded Type 11, Destination Unreachable Type 3), automated test client suite (`test/test_client.c`), packet injection harness, and Wireshark traffic verification. |

---

### System Architecture & Topology

The userspace router simulates physical network interfaces using POSIX threads bound to independent UDP sockets on local loopback, isolating layer-3 subnets without requiring root-level TUN/TAP kernel modules:

```text
       Subnet 1: 192.168.1.0/24                   Subnet 2: 192.168.2.0/24
      ┌─────────────────────────┐               ┌─────────────────────────┐
      │   [Source Host A]       │               │   [Destination Host B]  │
      │   IP:  192.168.1.10     │               │   IP:  192.168.2.20     │
      │   Port: 9001 (Simulated)│               │   Port: 9002 (Simulated)│
      └────────────┬────────────┘               └────────────▲────────────┘
                   │                                         │
                   ▼ (Ingress Link)                          │ (Egress Link)
            ┌──────────────┐                          ┌──────────────┐
            │   eth0       │                          │   eth1       │
            │   192.168.1.1│                          │   192.168.2.1│
            │   Port: 8001 │                          │   Port: 8002 │
            └──────┬───────┘                          └──────▲───────┘
                   │                                         │
                   └──────────────────┬──────────────────────┘
                                      │
                   ┌──────────────────┴──────────────────────┐
                   │        USERSPACE IP ROUTER              │
                   │                                         │
                   │  • LPM Routing Table Lookup (Trie)      │
                   │  • Dynamic ARP Cache & Queue Engine     │
                   │  • RFC 1071 Checksum & TTL Validation   │
                   │                                         │
                   │  eth2 (WAN / Gateway):                  │
                   │  IP: 10.0.0.1  |  Port: 8003            │
                   └──────────────────┬──────────────────────┘
