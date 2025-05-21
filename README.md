<div align="center">
  <h1>ESP8266 IEEE 802.11 Management Frame Toolkit</h1>
  
  <p>
    <img src="https://img.shields.io/badge/Platform-ESP8266-blue.svg" alt="Platform">
    <img src="https://img.shields.io/badge/Standard-IEEE%20802.11-ff69b4.svg" alt="IEEE 802.11">
    <img src="https://img.shields.io/badge/License-Educational%20%7C%20Research-important.svg" alt="License">
    <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
    <img src="https://img.shields.io/badge/Frames-Beacon%20%7C%20Assoc%20Req%20%7C%20Deauth%20%7C%20Disassoc-orange.svg" alt="Frames">
  </p>
</div>

---


<p align="center">
  <b>Craft, transmit, and study raw IEEE 802.11 management frames (Beacon, Association Request, Deauthentication, Disassociation) on the ESP8266.<br>
  Fully standards-compliant, highly educational, and visually documented.</b>
</p>

## 🚀 Features

- **IEEE 802.11-2016 Standard Compliance:**
  - All management frames (Beacon, Association Request, Deauthentication, Disassociation) are constructed per the IEEE 802.11-2016 standard.
  - Correct MAC header, fixed, and tagged parameters for each frame type.
- **User-Selectable Frame Type:**
  - Select frame type and set parameters (SSID, MAC, channel, reason code) via serial commands.
- **Automatic Parameter Handling:**
  - All relevant fields and buffers are set automatically for the selected frame type.
- **Robust Channel Hopping:**
  - Supports sequential, adaptive, and random channel hopping for maximum delivery and minimal interference.
- **Carrier Sensing:**
  - RSSI-based channel assessment to avoid busy channels.
- **Low-level Transmission:**
  - Uses ESP8266 SDK and direct register access for raw packet transmission.
- **Interactive Serial Interface:**
  - Manual and continuous transmission modes, debug output, and runtime configuration.
- **Detailed Documentation:**
  - Code and documentation reference relevant IEEE 802.11 sections and provide annotated, educational examples.

## 📡 Supported Frame Types

| Frame Type            | IEEE 802.11 Section | Description                                      |
|----------------------|---------------------|--------------------------------------------------|
| Beacon               | 9.4.1.3             | Announces AP presence and parameters              |
| Association Request  | 9.3.3.6             | Requests client association with AP               |
| Deauthentication     | 9.3.3.13            | Terminates authentication (force disconnect)      |
| Disassociation       | 9.3.3.12            | Gracefully ends association (client/AP disconnect)|

See [`sample/example.md`](IEEE-80211-8266/sample/example.md) for detailed, annotated code for each frame type.

## 🛠️ Getting Started
## 📥 Dependencies & Libraries

The project requires the following ESP8266 non-OS SDK headers:

```c
#include <user_interface.h>      // ESP8266 SDK core interface functions
#include <espnow.h>             // ESP-NOW protocol operations
#include <ieee80211_structs.h>   // IEEE 802.11 frame structures
#include <ets_sys.h>            // ESP8266 timer and system functions
```

These headers are included in the [ESP8266 RTOS SDK](https://github.com/espressif/ESP8266_RTOS_SDK) and [ESP8266 non-OS SDK](https://github.com/espressif/ESP8266_NONOS_SDK). When using Arduino IDE:

1. Install ESP8266 board support using Boards Manager URL:
   ```
   https://arduino.esp8266.com/stable/package_esp8266com_index.json
   ```
2. Install ESP8266 core (version 2.5.0 or later)
3. The required headers will be available in:
   ```
   $ARDUINO_DIR/hardware/esp8266com/esp8266/tools/sdk/include/
   ```


1. **Hardware:**
   - ESP8266 module (NodeMCU, Wemos D1 Mini, etc.)
2. **Software:**
   - Arduino IDE with ESP8266 board support
   - Place `IEEE-80211-8266.ino` in your sketch folder
3. **Upload:**
   - Select your ESP8266 board and upload the sketch
4. **Serial Commands:**
   - `type beacon` — Select Beacon frame
   - `type assoc` — Select Association Request frame
   - `type deauth` — Select Deauthentication frame
   - `type disassoc` — Select Disassociation frame
   - `ssid MyNetwork` — Set SSID
   - `mac 12:34:56:78:9A:BC` — Set MAC address
   - `channel 6` — Set channel
   - `reason 3` — Set reason code (for deauth/disassoc)
   - `send` — Transmit the frame
   - `help` — Show all commands
5. **Monitor Output:**
   - Serial output provides status, debug, and error messages.

## ⚠️ Terms, Disclaimer & Ethics

> **This project is for educational and research purposes only.**

- Transmitting arbitrary 802.11 management frames may disrupt WiFi networks and is subject to legal restrictions in many countries.
- The authors and contributors are not responsible for any misuse or damages caused by this code.
- Use only on networks and devices you own or have explicit permission to test.
- Always comply with your local laws and regulations regarding wireless transmissions.
- All use is at your own risk.

## 📝 Technical Notes
- The code uses packed C structs and manual buffer construction to ensure IEEE 802.11 compliance.
- All frame types are built according to the standard, including correct MAC header, fixed parameters, and required tagged parameters.
- Channel hopping and carrier sensing are implemented to maximize delivery and minimize interference.
- Inline assembly and direct register access are used for precise timing and raw transmission.

## 📚 References
- [IEEE 802.11-2016 Standard](https://standards.ieee.org/standard/802_11-2016.html)
- [ESP8266 SDK Documentation](https://docs.espressif.com/projects/esp8266-rtos-sdk/en/latest/esp8266/)
- [Arduino ESP8266 Core](https://github.com/esp8266/Arduino)
- [Wikipedia: IEEE 802.11 Management Frames](https://en.wikipedia.org/wiki/IEEE_802.11#Management_frames)

---
**By using this code, you agree to the above terms and accept all responsibility for its use.**
