#ifndef IEEE80211_STRUCTS_H
#define IEEE80211_STRUCTS_H

#include <stdint.h>
#include <ESP8266WiFi.h>

// Forward declaration of ESP8266 SDK function
extern "C" {
    int8_t system_get_rssi(void);
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

// External declarations
extern uint16_t sequence_number;
extern uint8_t channel_scan;
extern uint16_t sequence_number;

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

// Forward declarations of main functions
uint16_t build_beacon_packet(uint8_t* buffer, const uint8_t* bssid, const char* ssid, uint8_t channel);
uint16_t build_deauth_packet(uint8_t* buffer, const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason);
uint16_t build_disassoc_packet(uint8_t* buffer, const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason);
uint16_t build_association_packet(uint8_t* buffer, const uint8_t* dst_addr, const uint8_t* src_addr, const char* ssid, uint8_t channel);

// RSSI helper function declaration
static inline int8_t wifi_get_channel_rssi(void) {
    return (int8_t)WiFi.RSSI();
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
static inline void init_mgmt_frame_header(ieee80211_mac_header_t* hdr, 
                                        uint8_t subtype,
                                        const uint8_t* addr1,
                                        const uint8_t* addr2,
                                        const uint8_t* addr3) {
    hdr->frame_ctrl.protocol_version = 0;
    hdr->frame_ctrl.type = IEEE80211_TYPE_MANAGEMENT;
    hdr->frame_ctrl.subtype = subtype;
    hdr->frame_ctrl.to_ds = 0;
    hdr->frame_ctrl.from_ds = 0;
    hdr->frame_ctrl.more_frag = 0;
    hdr->frame_ctrl.retry = 0;
    hdr->frame_ctrl.power_mgmt = 0;
    hdr->frame_ctrl.more_data = 0;
    hdr->frame_ctrl.protected_frame = 0;
    hdr->frame_ctrl.order = 0;
    hdr->duration_id = 0;
    
    if (addr1) memcpy(hdr->addr1, addr1, 6);
    if (addr2) memcpy(hdr->addr2, addr2, 6);
    if (addr3) memcpy(hdr->addr3, addr3, 6);
}

/**
 * Add a tagged parameter to a buffer
 */
static inline uint16_t add_tagged_param(uint8_t* buffer, 
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

#ifdef __cplusplus
}
#endif

#endif // IEEE80211_STRUCTS_H
