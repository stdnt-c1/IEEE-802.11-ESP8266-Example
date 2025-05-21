#ifndef IEEE80211_STRUCTS_H
#define IEEE80211_STRUCTS_H

#include <stdint.h>
#include <ESP8266WiFi.h>

// Function declarations
void log_channel_hop(uint8_t new_channel, bool success, const char* reason = nullptr);

// Forward declaration of ESP8266 SDK function
extern "C" {
    int8_t system_get_rssi(void);
}

// Forward declare SSL error handling function
extern "C" ICACHE_RAM_ATTR int32_t ssl_error_handle(const char* msg) {
    return -1;  // Default error handler
}

// Frame type and subtype definitions
#define IEEE80211_TYPE_MANAGEMENT 0x00
#define IEEE80211_TYPE_CONTROL    0x01
#define IEEE80211_TYPE_DATA       0x02

// Management frame subtypes
#define IEEE80211_SUBTYPE_ASSOC_REQ    0x00
#define IEEE80211_SUBTYPE_BEACON       0x08
#define IEEE80211_SUBTYPE_DISASSOC     0x0A
#define IEEE80211_SUBTYPE_DEAUTH       0x0C

// External declarations - aligned for memory access
extern uint16_t sequence_number __attribute__((aligned(4)));
extern uint8_t channel_scan __attribute__((aligned(4)));

// ESP8266 SDK specific definitions
#ifndef ETS_WDEV_INTR_DISABLE
#define ETS_WDEV_INTR_DISABLE() ETS_UART_INTR_DISABLE()
#endif

#ifndef ETS_WDEV_INTR_ENABLE
#define ETS_WDEV_INTR_ENABLE() ETS_UART_INTR_ENABLE()
#endif

// Timer interrupt controls
#define ETS_FRC_TIMER1_INTR_DISABLE() ETS_FRC1_INTR_DISABLE()
#define ETS_FRC_TIMER1_INTR_ENABLE()  ETS_FRC1_INTR_ENABLE()

// Channel scanning helper
#define WIFI_CHANNEL_MAX 14
extern uint8_t channel_scan;

// Channel statistics for adaptive hopping
struct ChannelStats {
    uint32_t last_success __attribute__((aligned(4)));    // Timestamp of last successful transmission
    uint32_t status __attribute__((aligned(4)));          // Packed status: fail_count(8) | busy_count(8) | blacklisted(1)

    // Member functions for atomic operations
    ICACHE_RAM_ATTR inline void incrementFailCount() {
        uint32_t old_status;
        do {
            old_status = status;
            uint8_t fail_count = (old_status >> 16) & 0xFF;
            if (fail_count < 255) fail_count++;
            uint32_t new_status = (old_status & 0x0000FFFF) | (fail_count << 16);
            asm volatile ("rsil a15, 1\n\t"
                         "s32i %0, %1, 0\n\t"
                         "rsil a15, 0"
                         :
                         : "r" (new_status), "r" (&status)
                         : "a15", "memory");
        } while (status != old_status);
    }

    ICACHE_RAM_ATTR inline void resetFailCount() {
        uint32_t old_status;
        do {
            old_status = status;
            uint32_t new_status = old_status & 0x0000FFFF;
            asm volatile ("rsil a15, 1\n\t"
                         "s32i %0, %1, 0\n\t"
                         "rsil a15, 0"
                         :
                         : "r" (new_status), "r" (&status)
                         : "a15", "memory");
        } while (status != old_status);
    }

    ICACHE_RAM_ATTR inline void setBlacklisted(bool value) {
        uint32_t old_status;
        do {
            old_status = status;
            uint32_t new_status = (old_status & 0xFFFFFFFE) | (value ? 1 : 0);
            asm volatile ("rsil a15, 1\n\t"
                         "s32i %0, %1, 0\n\t"
                         "rsil a15, 0"
                         :
                         : "r" (new_status), "r" (&status)
                         : "a15", "memory");
        } while (status != old_status);
    }

    ICACHE_RAM_ATTR inline bool isBlacklisted() const {
        return (status & 0x01) != 0;
    }
};

#ifdef __cplusplus
extern "C" {
#endif

extern ChannelStats channel_stats[WIFI_CHANNEL_MAX + 1];

// Function declarations for packet building

ICACHE_RAM_ATTR uint16_t build_beacon_packet(uint8_t* buffer, const uint8_t* bssid, const char* ssid, uint8_t channel);
ICACHE_RAM_ATTR uint16_t build_deauth_packet(uint8_t* buffer, const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason);
ICACHE_RAM_ATTR uint16_t build_disassoc_packet(uint8_t* buffer, const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason);
ICACHE_RAM_ATTR uint16_t build_association_packet(uint8_t* buffer, const uint8_t* dst_addr, const uint8_t* src_addr, const char* ssid, uint8_t channel);

#ifdef __cplusplus
}
#endif

// RSSI helper function declaration
ICACHE_RAM_ATTR static inline int8_t wifi_get_channel_rssi(void) {
    static int8_t last_rssi = 0;
    int8_t current = (int8_t)WiFi.RSSI();
    if (current != 0) {
        last_rssi = current;
    }
    return last_rssi;
}

// Frame type and subtype definitions
#define IEEE80211_TYPE_MANAGEMENT 0x00
#define IEEE80211_TYPE_CONTROL    0x01
#define IEEE80211_TYPE_DATA       0x02

// Management frame subtypes
#define IEEE80211_SUBTYPE_ASSOC_REQ    0x00
#define IEEE80211_SUBTYPE_ASSOC_RESP   0x01
#define IEEE80211_SUBTYPE_PROBE_REQ    0x04
#define IEEE80211_SUBTYPE_PROBE_RESP   0x05
#define IEEE80211_SUBTYPE_BEACON       0x08
#define IEEE80211_SUBTYPE_DISASSOC     0x0A
#define IEEE80211_SUBTYPE_AUTH         0x0B
#define IEEE80211_SUBTYPE_DEAUTH       0x0C

// Common reason codes
#define IEEE80211_REASON_UNSPECIFIED          1
#define IEEE80211_REASON_AUTH_EXPIRE          2
#define IEEE80211_REASON_AUTH_LEAVING         3
#define IEEE80211_REASON_INACTIVE             4
#define IEEE80211_REASON_AP_FULL             5
#define IEEE80211_REASON_NOT_AUTHENTICATED    6
#define IEEE80211_REASON_NOT_ASSOCIATED       7

// Capability Information Bits
#define IEEE80211_CAP_ESS          0x0001
#define IEEE80211_CAP_IBSS         0x0002
#define IEEE80211_CAP_PRIVACY      0x0010
#define IEEE80211_CAP_SHORT_PMBL   0x0020

// Element IDs for tagged parameters
#define IEEE80211_ELEMID_SSID              0
#define IEEE80211_ELEMID_SUPP_RATES        1
#define IEEE80211_ELEMID_DS_PARAMS         3
#define IEEE80211_ELEMID_TIM               5
#define IEEE80211_ELEMID_COUNTRY           7
#define IEEE80211_ELEMID_EXT_SUPP_RATES    50
#define IEEE80211_ELEMID_HT_CAP           45

// Buffer alignment and max packet size
#define BUFFER_ALIGNMENT 4     // Required alignment for ESP8266 DMA
#define MAX_PACKET_SIZE 512    // Maximum packet size

/**
 * IEEE 802.11 Frame Control field structure (bitfield, packed)
 */
typedef struct {
    uint8_t protocol_version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t to_ds:1;
    uint8_t from_ds:1;
    uint8_t more_frag:1;
    uint8_t retry:1;
    uint8_t power_mgmt:1;
    uint8_t more_data:1;
    uint8_t protected_frame:1;
    uint8_t order:1;
    
    // Helper functions
    inline void setType(uint8_t t) { type = t; }
    inline void setSubtype(uint8_t st) { subtype = st; }
    inline void setManagementFrame() {
        type = IEEE80211_TYPE_MANAGEMENT;
        to_ds = 0;
        from_ds = 0;
    }
} __attribute__((packed)) frame_control_t;

/**
 * IEEE 802.11 MAC Header structure
 */
typedef struct {
    frame_control_t frame_ctrl;
    uint16_t duration_id;
    uint8_t addr1[6];  // Receiver Address
    uint8_t addr2[6];  // Transmitter Address
    uint8_t addr3[6];  // Destination Address or BSSID
    uint16_t seq_ctrl;
} __attribute__((packed)) ieee80211_mac_header_t;

/**
 * IEEE 802.11 Tagged Parameter structure
 */
typedef struct {
    uint8_t element_id;
    uint8_t length;
    uint8_t data[];  // Flexible array member
} __attribute__((packed)) ieee80211_tagged_param_t;

/**
 * IEEE 802.11 Beacon Frame Fixed Parameters
 */
typedef struct {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capability_info;
} __attribute__((packed)) beacon_fixed_params_t;

/**
 * IEEE 802.11 Deauthentication/Disassociation Frame Body
 */
typedef struct {
    uint16_t reason_code;
} __attribute__((packed)) deauth_disassoc_body_t;

/**
 * IEEE 802.11 Association Request Fixed Parameters
 */
typedef struct {
    uint16_t capability_info;
    uint16_t listen_interval;
} __attribute__((packed)) assoc_fixed_params_t;

// Helper functions for packet building
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize a management frame header
 */
ICACHE_RAM_ATTR static inline void init_mgmt_frame_header(ieee80211_mac_header_t* hdr, 
                                        uint8_t subtype,
                                        const uint8_t* addr1,
                                        const uint8_t* addr2,
                                        const uint8_t* addr3) {
    if (!hdr || !addr1 || !addr2 || !addr3) return;

    // Frame Control Field
    hdr->frame_ctrl.protocol_version = 0;  // Always 0 for current 802.11
    hdr->frame_ctrl.type = IEEE80211_TYPE_MANAGEMENT;
    hdr->frame_ctrl.subtype = subtype;
    hdr->frame_ctrl.to_ds = 0;    // Management frames never use DS
    hdr->frame_ctrl.from_ds = 0;  // Management frames never use DS
    hdr->frame_ctrl.more_frag = 0;
    hdr->frame_ctrl.retry = 0;
    hdr->frame_ctrl.power_mgmt = 0;
    hdr->frame_ctrl.more_data = 0;
    hdr->frame_ctrl.protected_frame = 0;  // No encryption for management frames
    hdr->frame_ctrl.order = 0;

    // Duration/ID field - typically 0 for management frames
    hdr->duration_id = 0;

    // MAC addresses - must be properly aligned
    memcpy(hdr->addr1, addr1, 6);  // Destination
    memcpy(hdr->addr2, addr2, 6);  // Source
    memcpy(hdr->addr3, addr3, 6);  // BSSID

    // Let sequence control be handled by caller
}

/**
 * Add a tagged parameter to a buffer
 */
ICACHE_RAM_ATTR static inline uint16_t add_tagged_param(uint8_t* buffer, 
                                      uint8_t element_id,
                                      uint8_t length,
                                      const uint8_t* data) {
    buffer[0] = element_id;
    buffer[1] = length;
    if (data && length > 0) {
        memcpy(buffer + 2, data, length);
    }
    return length + 2;
}

// Frame validation helper functions
ICACHE_RAM_ATTR static inline bool validate_mac_frame(const ieee80211_mac_header_t* hdr,
                                                    uint8_t expected_type,
                                                    uint8_t expected_subtype) {
    if (!hdr) return false;

    // Check protocol version (must be 0 for current 802.11)
    if (hdr->frame_ctrl.protocol_version != 0) return false;

    // Verify frame type and subtype
    if (hdr->frame_ctrl.type != expected_type ||
        hdr->frame_ctrl.subtype != expected_subtype) return false;

    // Management frames should not use distribution system
    if (expected_type == IEEE80211_TYPE_MANAGEMENT &&
        (hdr->frame_ctrl.to_ds || hdr->frame_ctrl.from_ds)) return false;

    return true;
}

ICACHE_RAM_ATTR static inline bool validate_tagged_params(const uint8_t* buffer,
                                                        uint16_t length,
                                                        uint16_t offset) {
    while (offset < length - 2) {  // Need at least element ID and length
        uint8_t id = buffer[offset];
        uint8_t len = buffer[offset + 1];
        
        // Check if parameter extends beyond packet
        if (offset + 2 + len > length) return false;
        
        // Move to next parameter
        offset += 2 + len;
    }
    return true;
}

ICACHE_RAM_ATTR static inline bool validate_reason_code(uint16_t reason, bool is_deauth) {
    if (reason == 0) return false;
    
    if (is_deauth) {
        // Deauthentication reason codes: 1-36
        return reason <= 0x0024;
    } else {
        // Disassociation reason codes: 1-8
        return reason <= 0x0008;
    }
}

// Channel management helper functions
// Channel helper functions
ICACHE_RAM_ATTR static inline bool wifi_set_safe_channel(uint8_t channel) {
    if (channel < 1 || channel > 14) {
        log_channel_hop(channel, false, "Invalid channel");
        return false;
    }
    bool success = wifi_set_channel(channel);
    if (success) {
        delayMicroseconds(500);  // Let channel switch settle
        system_soft_wdt_feed();  // Feed watchdog during channel switch
        log_channel_hop(channel, true);
    } else {
        log_channel_hop(channel, false, "Channel switch failed");
    }
    return success;
}

#ifdef __cplusplus
}  // extern "C"
#endif

// Get debug information about channel stats
ICACHE_RAM_ATTR static inline void get_channel_stats_debug(uint8_t channel, 
                                                         uint8_t& fail_count, 
                                                         uint8_t& busy_count, 
                                                         bool& blacklisted) {
    uint32_t status = channel_stats[channel].status;
    fail_count = (status >> 16) & 0xFF;
    busy_count = (status >> 8) & 0xFF;
    blacklisted = (status & 0x01) != 0;
}

#endif // IEEE80211_STRUCTS_H
