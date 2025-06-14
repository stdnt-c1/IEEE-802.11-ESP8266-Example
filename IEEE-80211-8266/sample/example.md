# IEEE 802.11 Management Frame Structure Examples

## Legal Notice and Disclaimer

⚠️ **IMPORTANT SAFETY AND LEGAL WARNINGS** ⚠️

This documentation and associated code are provided for **EDUCATIONAL AND RESEARCH PURPOSES ONLY**. 

**CRITICAL WARNINGS:**
1. Unauthorized access or interference with networks may be illegal in your jurisdiction
2. Improper use can disrupt network operations and affect other devices
3. Users are solely responsible for ensuring compliance with:
   - Local and national telecommunications laws
   - Radio frequency regulations
   - Computer misuse legislation
   - Network security policies
   - Terms of service agreements

**LIMITATIONS:**
- No warranty of fitness for any purpose
- Authors assume no liability for any damages
- Use at your own risk

By using this code, you acknowledge these risks and accept full responsibility for compliance.

## Framework Version
- IEEE 802.11-2016 Standard Implementation
- ESP8266 Arduino Core 3.1.2 Compatible
- Last Updated: May 21, 2025

## Command Interface Reference

Available Serial Commands:
| Command | Description | Example |
|---------|-------------|----------|
| t | Trigger single transmission | t |
| c | Toggle continuous mode | c |
| d | Toggle debug mode | d |
| h | Show help menu | h |
| s | Show current status | s |
| m | Set target MAC address | m FF:FF:FF:FF:FF:FF |
| f | Select frame type (0-3) | f |
| n | Set SSID | n TestNetwork |
| r | Set reason code | r 0001 |
| 1-9 | Set WiFi channel (1-9) | 5 |

Status Display Information:
- Continuous Mode: ON/OFF state
- Debug Mode: ON/OFF state
- Current Channel: Active WiFi channel
- Target MAC: Destination MAC address
- Source MAC: Origin MAC address
- SSID: Network name
- Frame Type: Selected frame type (0-3)
- Reason Code: Used in deauth/disassoc frames

## Frame Type Reference
0. Association Request
1. Beacon
2. Deauthentication
3. Disassociation

## General Frame Structure
All management frames follow this basic structure:

| Data Frame Sections                        |
|:-------------------------------------------|
| MAC Header (24 bytes)                      |
| Frame-specific Fixed Fields                |
| Tagged Parameters (Information Elements)   |
| Frame Check Sequence (4 bytes)             |

## References and Documentation

### Primary References
- [IEEE 802.11-2016 Standard](https://standards.ieee.org/standard/802_11-2016.html)
- [ESP8266 SDK Documentation](https://docs.espressif.com/projects/esp8266-rtos-sdk/en/latest/esp8266/)
- [Arduino ESP8266 Core](https://github.com/esp8266/Arduino)

### Frame Type References
- [IEEE 802.11 Frame Types Overview](https://en.wikipedia.org/wiki/802.11_Frame_Types)
- [Management Frame Specifications](https://en.wikipedia.org/wiki/802.11_Frame_Types#Management_frames)
- [Frame Structure Details](https://en.wikipedia.org/wiki/IEEE_802.11#Frame_structure)

---

## Frame Building Details

### Frame Type 0: Association Request
```cpp
// Basic structure of an Association Request frame
[MAC Header: 24 bytes]
- Frame Control (2 bytes)
- Duration (2 bytes)
- Address 1: Destination/BSSID (6 bytes)
- Address 2: Source (6 bytes)
- Address 3: BSSID (6 bytes)
- Sequence Control (2 bytes)

[Fixed Fields: 4 bytes]
- Capability Information (2 bytes)
- Listen Interval (2 bytes)

[Tagged Parameters]
- SSID (Variable)
- Supported Rates (Variable)
- Extended Supported Rates (Optional)
- HT Capabilities (Optional)
```

### Frame Type 1: Beacon
```cpp
// Basic structure of a Beacon frame
[MAC Header: 24 bytes]
- Frame Control (2 bytes)
- Duration (2 bytes)
- Address 1: Broadcast FF:FF:FF:FF:FF:FF (6 bytes)
- Address 2: Source/BSSID (6 bytes)
- Address 3: BSSID (6 bytes)
- Sequence Control (2 bytes)

[Fixed Fields: 12 bytes]
- Timestamp (8 bytes)
- Beacon Interval (2 bytes)
- Capability Information (2 bytes)

[Tagged Parameters]
- SSID (Variable)
- Supported Rates (Variable)
- DS Parameter Set (3 bytes)
- TIM (Variable)
- Country (Variable, Optional)
```

### Frame Type 2: Deauthentication
```cpp
// Basic structure of a Deauthentication frame
[MAC Header: 24 bytes]
- Frame Control (2 bytes)
- Duration (2 bytes)
- Address 1: Destination (6 bytes)
- Address 2: Source (6 bytes)
- Address 3: BSSID (6 bytes)
- Sequence Control (2 bytes)

[Fixed Fields: 2 bytes]
- Reason Code (2 bytes)

[Optional]
- Supported Rates
```

### Frame Type 3: Disassociation
```cpp
// Basic structure of a Disassociation frame
[MAC Header: 24 bytes]
- Frame Control (2 bytes)
- Duration (2 bytes)
- Address 1: Destination (6 bytes)
- Address 2: Source (6 bytes)
- Address 3: BSSID (6 bytes)
- Sequence Control (2 bytes)

[Fixed Fields: 2 bytes]
- Reason Code (2 bytes)

[Optional]
- Supported Rates
```

## Core Implementation Notes

### Sequence Number Handling
- 12-bit sequence number (0-4095)
- Atomic increment operation
- Wraps around after 4095
- Used in all frame types

### Channel Management
- Channel range: 1-14 (region dependent)
- Dwell time between channel switches
- RSSI-based clear channel assessment
- Three hopping strategies:
  1. Sequential
  2. Random
  3. Adaptive (based on channel conditions)

### Frame Control Field Structure
```cpp
struct frame_control {
    uint16_t protocol_version:2;
    uint16_t type:2;
    uint16_t subtype:4;
    uint16_t to_ds:1;
    uint16_t from_ds:1;
    uint16_t more_frag:1;
    uint16_t retry:1;
    uint16_t power_mgmt:1;
    uint16_t more_data:1;
    uint16_t protected_frame:1;
    uint16_t order:1;
};
```

## Core SDK Functions
```cpp
// Essential ESP8266 SDK functions used
wifi_set_channel(uint8 channel)
wifi_send_pkt_freedom(uint8 *buffer, uint16 len, bool sys_seq)
system_get_free_heap_size()
ets_delay_us(uint32_t us)
```

## Implementation Best Practices

1. Memory Management
   - Use ICACHE_RAM_ATTR for critical functions
   - Align buffers to 4-byte boundaries
   - Pre-allocate fixed-size buffers

2. Timing Considerations
   - Respect minimum frame spacing
   - Include proper inter-frame gaps
   - Monitor and adjust dwell time

3. Error Handling
   - Track transmission success/failure
   - Implement retry mechanism
   - Monitor channel conditions

4. Channel Management
   - Implement clear channel assessment
   - Track channel statistics
   - Adapt hopping strategy

---

## Management Frame Implementations

### Association Request Frame
**Reference:** IEEE 802.11-2016, Section 9.3.3.6

#### Frame Structure

| Section                             | Details                           |
|:------------------------------------|:----------------------------------|
| **MAC Header** | 24 bytes                          |
| **Capability Information** | 2 bytes                           |
| **Listen Interval** | 2 bytes                           |
| **SSID Element** | (Information Element)             |
| **Supported Rates** | (Information Element)             |
| **HT Capabilities** | (Information Element)             |
| **Other Elements** | (Information Element)             |

```cpp
// Builds an Association Request frame for joining an AP
uint16_t build_association_packet(uint8_t* buffer, const uint8_t* dst_addr, const uint8_t* src_addr, const char* ssid, uint8_t channel) {
  memset(buffer, 0, 512);
  uint16_t pos = 0;
  // --- MAC Header (24 bytes) ---
  ieee80211_mac_header_t* header = (ieee80211_mac_header_t*)buffer;
  header->frame_ctrl.protocol_version = 0; // Always 0
  header->frame_ctrl.type = 0;             // Management frame
  header->frame_ctrl.subtype = 0;          // Association Request
  header->frame_ctrl.to_ds = 0;
  header->frame_ctrl.from_ds = 0;
  header->frame_ctrl.more_frag = 0;
  header->frame_ctrl.retry = 0;
  header->frame_ctrl.power_mgmt = 0;
  header->frame_ctrl.more_data = 0;
  header->frame_ctrl.protected_frame = 0;
  header->frame_ctrl.order = 0;
  header->duration_id = 0;
  memcpy(header->addr1, dst_addr, 6); // Destination (AP/BSSID)
  memcpy(header->addr2, src_addr, 6); // Source (Station)
  memcpy(header->addr3, dst_addr, 6); // BSSID (AP)
  header->seq_ctrl = sequence_number++ << 4;
  pos += sizeof(ieee80211_mac_header_t);
  // --- Fixed Parameters (4 bytes) ---
  assoc_fixed_params_t* fixed_params = (assoc_fixed_params_t*)(buffer + pos);
  fixed_params->capability_info = 0x0011; // ESS, Privacy
  fixed_params->listen_interval = 0x000A; // 10 beacon intervals
  pos += sizeof(assoc_fixed_params_t);
  // --- Tagged Parameters (Information Elements) ---
  // SSID
  buffer[pos++] = 0x00; // Element ID: SSID
  uint8_t ssid_len = strlen(ssid);
  buffer[pos++] = ssid_len;
  memcpy(buffer + pos, ssid, ssid_len); pos += ssid_len;
  // Supported Rates
  buffer[pos++] = 0x01; buffer[pos++] = 0x08;
  buffer[pos++] = 0x82; buffer[pos++] = 0x84; buffer[pos++] = 0x8B; buffer[pos++] = 0x96;
  buffer[pos++] = 0x0C; buffer[pos++] = 0x12; buffer[pos++] = 0x18; buffer[pos++] = 0x24;
  // Extended Supported Rates
  buffer[pos++] = 0x32; buffer[pos++] = 0x04;
  buffer[pos++] = 0x30; buffer[pos++] = 0x48; buffer[pos++] = 0x60; buffer[pos++] = 0x6C;
  // HT Capabilities (optional, for 802.11n)
  buffer[pos++] = 0x2D; buffer[pos++] = 0x1A; // Element ID, Length
  buffer[pos++] = 0x01; buffer[pos++] = 0x00; // HT Capabilities Info
  buffer[pos++] = 0x00; // A-MPDU Parameters
  for (int i = 0; i < 16; i++) buffer[pos++] = (i < 2) ? 0xFF : 0x00; // Supported MCS Set
  buffer[pos++] = 0x00; buffer[pos++] = 0x00; // HT Extended Capabilities
  buffer[pos++] = 0x00; buffer[pos++] = 0x00; buffer[pos++] = 0x00; buffer[pos++] = 0x00; // Beamforming
  buffer[pos++] = 0x00; // ASEL Capabilities
  // Power Capability (optional)
  buffer[pos++] = 0x21; buffer[pos++] = 0x02; buffer[pos++] = 0x00; buffer[pos++] = 0x64;
  // Supported Channels (optional)
  buffer[pos++] = 0x24; buffer[pos++] = 0x02; buffer[pos++] = 0x01; buffer[pos++] = 0x0B;
  // DS Parameter Set (critical for channel)
  buffer[pos++] = 0x03; buffer[pos++] = 0x01; buffer[pos++] = channel;
  // Note: FCS (4 bytes) is appended by hardware
  return pos;
}
```
Field Details:
- `capability_info`: 0x0011 indicates ESS and Privacy capabilities
- `listen_interval`: Time station will listen for beacons (in beacon intervals)
- `Supported Rates`: Basic rates all stations must support
- `HT Capabilities`: Optional 802.11n high throughput features

---

### Beacon Frame
**Reference:** IEEE 802.11-2016, Section 9.3.3.3

#### Frame Structure

| Field Name             | Size      | Notes                                  |
|:-----------------------|:----------|:---------------------------------------|
| **MAC Header** | 24 bytes  |                                        |
| **Timestamp** | 8 bytes   |                                        |
| **Beacon Interval** | 2 bytes   | Part of Frame-specific Fixed Fields    |
| **Capability Info** | 2 bytes   | Part of Frame-specific Fixed Fields    |
| **Tagged Parameters** | Varies    | Includes elements like SSID, Supported Rates, etc. |

```cpp
// Builds a Beacon frame for announcing a network
uint16_t build_beacon_packet(uint8_t* buffer, const uint8_t* bssid, const char* ssid, uint8_t channel) {
  memset(buffer, 0, 512);
  uint16_t pos = 0;
  // --- MAC Header (24 bytes) ---
  ieee80211_mac_header_t* header = (ieee80211_mac_header_t*)buffer;
  header->frame_ctrl.protocol_version = 0;
  header->frame_ctrl.type = 0; // Management
  header->frame_ctrl.subtype = 8; // Beacon
  header->frame_ctrl.to_ds = 0;
  header->frame_ctrl.from_ds = 0;
  header->frame_ctrl.more_frag = 0;
  header->frame_ctrl.retry = 0;
  header->frame_ctrl.power_mgmt = 0;
  header->frame_ctrl.more_data = 0;
  header->frame_ctrl.protected_frame = 0;
  header->frame_ctrl.order = 0;
  header->duration_id = 0;
  memcpy(header->addr1, "\xff\xff\xff\xff\xff\xff", 6); // Broadcast
  memcpy(header->addr2, bssid, 6); // Source (BSSID)
  memcpy(header->addr3, bssid, 6); // BSSID
  header->seq_ctrl = sequence_number++ << 4;
  pos += sizeof(ieee80211_mac_header_t);
  // --- Fixed parameters ---
  for (int i = 0; i < 8; i++) buffer[pos++] = 0x00; // Timestamp
  buffer[pos++] = 0x64; buffer[pos++] = 0x00; // Beacon interval
  buffer[pos++] = 0x31; buffer[pos++] = 0x04; // Capability info
  // --- Tagged parameters ---
  buffer[pos++] = 0x00; uint8_t ssid_len = strlen(ssid); buffer[pos++] = ssid_len; memcpy(buffer + pos, ssid, ssid_len); pos += ssid_len; // SSID
  buffer[pos++] = 0x01; buffer[pos++] = 0x08; buffer[pos++] = 0x82; buffer[pos++] = 0x84; buffer[pos++] = 0x8B; buffer[pos++] = 0x96; buffer[pos++] = 0x0C; buffer[pos++] = 0x12; buffer[pos++] = 0x18; buffer[pos++] = 0x24; // Supported Rates
  buffer[pos++] = 0x32; buffer[pos++] = 0x04; buffer[pos++] = 0x30; buffer[pos++] = 0x48; buffer[pos++] = 0x60; buffer[pos++] = 0x6C; // Extended Supported Rates
  buffer[pos++] = 0x03; buffer[pos++] = 0x01; buffer[pos++] = channel; // DS Parameter Set
  buffer[pos++] = 0x05; buffer[pos++] = 0x04; buffer[pos++] = 0x00; buffer[pos++] = 0x01; buffer[pos++] = 0x00; buffer[pos++] = 0x00; // TIM
  buffer[pos++] = 0x07; buffer[pos++] = 0x06; buffer[pos++] = 'U'; buffer[pos++] = 'S'; buffer[pos++] = 0x01; buffer[pos++] = 0x01; buffer[pos++] = 0x0B; buffer[pos++] = 0x0B; // Country Info
  return pos;
}
```
Field Details:
- `Timestamp`: 8-byte value for synchronization and timing
- `Beacon Interval`: Time between beacon transmissions (in TUs)
- `Capability Info`: Network capabilities (ESS, Privacy, etc.)
- `DS Parameter Set`: Current operating channel
- `TIM`: Traffic indication for power-saving stations

---

### Deauthentication Frame
**Reference:** IEEE 802.11-2016, Section 9.3.3.13

#### Frame Structure

| Field Name      | Size     |
|:----------------|:---------|
| **MAC Header** | 24 bytes |
| **Reason Code** | 2 bytes  |

```cpp
// Builds a Deauthentication frame to force a client to disconnect
uint16_t build_deauth_packet(uint8_t* buffer, const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason) {
  memset(buffer, 0, 512);
  uint16_t pos = 0;
  ieee80211_mac_header_t* header = (ieee80211_mac_header_t*)buffer;
  header->frame_ctrl.protocol_version = 0;
  header->frame_ctrl.type = 0; // Management
  header->frame_ctrl.subtype = 12; // Deauthentication
  header->frame_ctrl.to_ds = 0;
  header->frame_ctrl.from_ds = 0;
  header->frame_ctrl.more_frag = 0;
  header->frame_ctrl.retry = 0;
  header->frame_ctrl.power_mgmt = 0;
  header->frame_ctrl.more_data = 0;
  header->frame_ctrl.protected_frame = 0;
  header->frame_ctrl.order = 0;
  header->duration_id = 0;
  memcpy(header->addr1, dst, 6);
  memcpy(header->addr2, src, 6);
  memcpy(header->addr3, bssid, 6);
  header->seq_ctrl = sequence_number++ << 4;
  pos += sizeof(ieee80211_mac_header_t);
  // Reason code (2 bytes, little endian)
  buffer[pos++] = reason & 0xFF;
  buffer[pos++] = (reason >> 8) & 0xFF;
  // (Optional) add supported rates for some APs/clients
  // buffer[pos++] = 0x01; buffer[pos++] = 0x08;
  // buffer[pos++] = 0x82; buffer[pos++] = 0x84; buffer[pos++] = 0x8B; buffer[pos++] = 0x96;
  // buffer[pos++] = 0x0C; buffer[pos++] = 0x12; buffer[pos++] = 0x18; buffer[pos++] = 0x24;
  return pos;
}
```
Common Reason Codes:
- `1`: Unspecified reason
- `2`: Previous authentication invalid
- `3`: Station leaving BSS/IBSS
- `4`: Inactivity timeout
- `6`: Class 2 frame from non-authenticated station
- `7`: Class 3 frame from non-associated station
- `8`: Station leaving BSS/IBSS

---

### Disassociation Frame
**Reference:** IEEE 802.11-2016, Section 9.3.3.12

#### Frame Structure

| Field Name      | Size     |
|:----------------|:---------|
| **MAC Header** | 24 bytes |
| **Reason Code** | 2 bytes  |

```cpp
// Builds a Disassociation frame to gracefully disconnect a client
uint16_t build_disassoc_packet(uint8_t* buffer, const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason) {
  memset(buffer, 0, 512);
  uint16_t pos = 0;
  ieee80211_mac_header_t* header = (ieee80211_mac_header_t*)buffer;
  header->frame_ctrl.protocol_version = 0;
  header->frame_ctrl.type = 0; // Management
  header->frame_ctrl.subtype = 10; // Disassociation
  header->frame_ctrl.to_ds = 0;
  header->frame_ctrl.from_ds = 0;
  header->frame_ctrl.more_frag = 0;
  header->frame_ctrl.retry = 0;
  header->frame_ctrl.power_mgmt = 0;
  header->frame_ctrl.more_data = 0;
  header->frame_ctrl.protected_frame = 0;
  header->frame_ctrl.order = 0;
  header->duration_id = 0;
  memcpy(header->addr1, dst, 6);
  memcpy(header->addr2, src, 6);
  memcpy(header->addr3, bssid, 6);
  header->seq_ctrl = sequence_number++ << 4;
  pos += sizeof(ieee80211_mac_header_t);
  // Reason code (2 bytes, little endian)
  buffer[pos++] = reason & 0xFF;
  buffer[pos++] = (reason >> 8) & 0xFF;
  // (Optional) add supported rates for some APs/clients
  // buffer[pos++] = 0x01; buffer[pos++] = 0x08;
  // buffer[pos++] = 0x82; buffer[pos++] = 0x84; buffer[pos++] = 0x8B; buffer[pos++] = 0x96;
  // buffer[pos++] = 0x0C; buffer[pos++] = 0x12; buffer[pos++] = 0x18; buffer[pos++] = 0x24;
  return pos;
}
```
Reason Codes (Same as Deauthentication):
- `1`: Unspecified reason
- `2`: Previous authentication invalid
- `3`: Station leaving BSS/IBSS
- `4`: Inactivity timeout
- `8`: Station leaving BSS/IBSS

---

### Probe Request Frame
**Reference:** IEEE 802.11-2016, Section 9.3.3.9

#### Frame Structure

| Field Name        | Notes                   |
|:------------------|:------------------------|
| **MAC Header** | 24 bytes                |
| **SSID Element** | Tagged Parameter        |
| **Supported Rates** | Tagged Parameter        |
| **Extended Rates**| Tagged Parameter        |
| **HT Capabilities** | Tagged Parameter        |

```cpp
// Builds a Probe Request frame to discover networks
uint16_t build_probe_request(uint8_t* buffer, const uint8_t* src_addr, const char* ssid) {
    memset(buffer, 0, 512);
    uint16_t pos = 0;
    
    // MAC Header
    ieee80211_mac_header_t* header = (ieee80211_mac_header_t*)buffer;
    header->frame_ctrl.protocol_version = 0;
    header->frame_ctrl.type = 0; // Management
    header->frame_ctrl.subtype = 4; // Probe Request
    header->frame_ctrl.to_ds = 0;
    header->frame_ctrl.from_ds = 0;
    header->frame_ctrl.more_frag = 0;
    header->frame_ctrl.retry = 0;
    header->frame_ctrl.power_mgmt = 0;
    header->frame_ctrl.more_data = 0;
    header->frame_ctrl.protected_frame = 0;
    header->frame_ctrl.order = 0;
    header->duration_id = 0;
    
    // Broadcast destination
    memcpy(header->addr1, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(header->addr2, src_addr, 6);
    memcpy(header->addr3, "\xff\xff\xff\xff\xff\xff", 6);
    header->seq_ctrl = sequence_number++ << 4;
    pos += sizeof(ieee80211_mac_header_t);

    // SSID Element
    buffer[pos++] = 0x00; // Element ID: SSID
    buffer[pos++] = strlen(ssid);
    memcpy(buffer + pos, ssid, strlen(ssid));
    pos += strlen(ssid);

    // Supported Rates
    buffer[pos++] = 0x01; buffer[pos++] = 0x08;
    buffer[pos++] = 0x82; buffer[pos++] = 0x84;
    buffer[pos++] = 0x8B; buffer[pos++] = 0x96;
    buffer[pos++] = 0x0C; buffer[pos++] = 0x12;
    buffer[pos++] = 0x18; buffer[pos++] = 0x24;

    return pos;
}
```

## Packet Capture Examples

To analyze and verify the frame structures, you can use Wireshark with an ESP8266 in monitor mode. Here are example captures for each frame type:

### Association Request Capture
```
Frame 1234 (54 bytes on wire, 54 bytes captured)
IEEE 802.11 Association Request, Flags: ....
    Type/Subtype: Association Request (0x00)
    Frame Control: 0x0000
    Duration: 0
    Destination: Broadcast (ff:ff:ff:ff:ff:ff)
    Source: xx:xx:xx:xx:xx:xx
    BSS Id: xx:xx:xx:xx:xx:xx
    Fragment number: 0
    Sequence number: 1234
    Frame check sequence: 0x12345678
    Capability Information: 0x0411
    Listen Interval: 10
    Tagged parameters:
        SSID: "Test Network"
        Supported rates: 1.0 2.0 5.5 11.0 6.0 9.0 12.0 18.0 Mbps
```

For more packet capture examples and analysis, refer to the [Wireshark Wiki](https://wiki.wireshark.org/IEEE_802.11).

## Safety Features and Error Handling

1. Memory Safety
   - DMA-aligned buffer operations
   - Buffer overflow protection
   - Atomic sequence number handling
   - ISR-safe function implementation

2. Input Validation
   - MAC address format verification
   - SSID length checks (max 32 bytes)
   - Valid channel range (1-14)
   - Frame type validation

3. Hardware Protection
   - Channel hopping delays
   - Watchdog feeding
   - Hardware ready checks
   - Transmission power management

4. Error Recovery
   - Automatic retry mechanism
   - Channel blacklisting
   - Adaptive hopping strategy
   - Transmission timeout handling

## Responsible Usage Guidelines

1. Always obtain proper authorization before testing
2. Use only on networks you own or have permission to test
3. Follow local regulations regarding RF transmission
4. Maintain appropriate transmission power levels
5. Avoid network disruption or interference

## Troubleshooting Guide

### Common Issues and Solutions

1. **Sequence Number Issues**
   - Symptom: Frame sequence numbers not incrementing properly
   - Solution: Verify get_next_sequence() is being called atomically
   - Check: Monitor sequence values in debug mode with 'd' command

2. **Frame Transmission Failures**
   - Symptom: No acknowledgment from target
   - Solutions:
     - Verify channel matches target (use 's' command)
     - Check MAC address format is correct
     - Ensure proper frame type selection

3. **Compilation Errors**
   - Issue: undefined reference to 'get_next_sequence'
     - Solution: Include ieee80211_structs.h
   - Issue: redefinition of variables
     - Solution: Check scope of frame builder variables

4. **Debug Tips**
   - Use 'd' command to enable debug logging
   - Monitor frame transmission with 'l' command
   - Use 'e' to focus on error messages only
   - Check sequence numbers with 's' command

### Performance Optimization
- Keep frame building functions in ICACHE_RAM_ATTR
- Minimize operations in interrupt context
- Use appropriate delay between frame transmissions
- Monitor memory usage in continuous mode
