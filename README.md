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
- Display filter used: udp.port == 8001 || udp.port == 8002 || udp.port == 8003 || udp.port == 9001 || udp.port == 9002
- Router interface ports: UDP 8001, 8002 and 8003
- Test client response port: UDP 9001
- Forwarding destination port: UDP 9002

Capture file: captures/review1_forwarding_demo.pcapng

### Implementation Note
The current prototype uses custom simulated packets transported over UDP.
The ICMP message types are encoded within the custom packet payload.
This does not yet demonstrate native ICMP over IPv4 through TUN/TAP
or a Mininet topology.
### Verification Status

**Verified**
- Project compiles successfully using `make clean && make`.
- Normal forwarding was observed at the UDP receiver on port 9002.
- ICMP Time Exceeded (type 11, code 0) was received for TTL expiry.
- ICMP Echo Reply (type 0, code 0) was received.
- ICMP Destination Unreachable (type 3, code 1) was received.
- Automated test client completed all four test cases.

**Pending**
- Native IPv4 forwarding through a TUN/TAP interface.
- Mininet-based network testing.
- End-to-end native `ping` and `traceroute`.
- Verification of IPv4 header checksum updates when TTL is decremented.

**Scope note:** The verified tests use custom simulated packets transported over UDP. They do not establish that native IPv4 routing works end to end.