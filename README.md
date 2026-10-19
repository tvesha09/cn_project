## Member 3: ICMP, Validation and Diagnostics

### Implemented Features
- ICMP checksum calculation.
- Simulated ICMP Echo Request and Echo Reply.
- ICMP Time Exceeded response when TTL is 1.
- ICMP Destination Unreachable response when ARP resolution fails.
- UDP-based test client for sending packets and checking ICMP responses.

### Test Results

| Test | Expected Result | Status |
|---|---|---|
| Normal forwarding | Packet forwarded with TTL decremented | Passed |
| TTL expiry | ICMP type 11, code 0 | Passed |
| Echo Reply | ICMP type 0, code 0 | Passed |
| Destination Unreachable | ICMP type 3, code 1 | Received |

### Wireshark Evidence
- Capture interface: lo0 (Loopback)
- Display filter: udp.port == 9001
- Router interface ports: UDP 8001, 8002 and 8003
- Test client response port: UDP 9001
- Forwarding destination port: UDP 9002

Capture file: cn_project_icmp_tests.pcapng

### Implementation Note
The current prototype uses custom simulated packets transported over UDP.
The ICMP message types are encoded within the custom packet payload.
This does not yet demonstrate native ICMP over IPv4 through TUN/TAP
or a Mininet topology.