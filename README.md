<div align="center">
  <h1>ESP8266 IEEE 802.11 Management Frame Toolkit</h1>
  
  <p>
    <img src="https://img.shields.io/badge/Version-2.0.0-blue.svg" alt="Version">
    <img src="https://img.shields.io/badge/Platform-ESP8266-blue.svg" alt="Platform">
    <img src="https://img.shields.io/badge/Standard-IEEE%20802.11--2016-ff69b4.svg" alt="IEEE 802.11">
    <img src="https://img.shields.io/badge/License-Educational%20%7C%20Research-important.svg" alt="License">
    <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
    <img src="https://img.shields.io/badge/Frames-Beacon%20%7C%20Assoc%20%7C%20Deauth%20%7C%20Disassoc-orange.svg" alt="Frames">
    <img src="https://img.shields.io/badge/Updated-May%2021%2C%202025-yellow.svg" alt="Last Updated">
  </p>

  <p>
    <b>ESP8266 Framework Version:</b> 3.1.2<br>
    <b>SDK Version:</b> 3.0.5<br>
    <b>IEEE Standard:</b> 802.11-2016<br>
    <b>Build Date:</b> May 21, 2025
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
   - `t` — Trigger single transmission
   - `c` — Toggle continuous mode
   - `d` — Toggle debug mode
   - `h` — Show help menu
   - `s` — Show current status
   - `m` — Set target MAC (format: XX:XX:XX:XX:XX:XX)
   - `f` — Select frame type:
     - `0` - Association Request
     - `1` - Beacon
     - `2` - Deauthentication
     - `3` - Disassociation
   - `n` — Set network SSID
   - `r` — Set reason code (for deauth/disassoc)
   - `1-9` — Set WiFi channel (1-9)

   Use `h` to show the help menu or `s` to display current settings including:
   - Continuous/Debug mode status
   - Current channel
   - Target/Source MAC addresses
   - SSID and Frame type
   - Reason code (for deauth/disassoc)
5. **Monitor Output:**
   - Serial output provides status, debug, and error messages.

## ⚠️ Terms, Disclaimer & Ethics

**CRITICAL SAFETY AND LEGAL NOTICE**

This project is provided **STRICTLY FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**. Users must:

1. **Legal Compliance**
   - Ensure all usage complies with local/national laws
   - Obtain necessary authorizations before testing
   - Follow telecommunications regulations
   - Respect network security policies

2. **Safety Considerations**
   - Never use on production/live networks
   - Test only in controlled environments
   - Maintain proper documentation of testing
   - Monitor for unintended interference

3. **Ethical Guidelines**
   - Use only for learning/research
   - Never attempt unauthorized access
   - Document all testing procedures
   - Report vulnerabilities responsibly

**DISCLAIMERS:**
- No warranty of fitness for any purpose
- Authors assume no liability for damages
- Use at your own risk
- No support for malicious use

By using this code, you acknowledge these terms and accept full responsibility.

## 🔄 Recent Updates

### Version 2.0 (May 2025)
- Added atomic sequence number handling
- Improved frame builder error checking
- Enhanced documentation and safety warnings
- Added troubleshooting guide
- Updated command interface reference

### Known Issues
- See troubleshooting section in example.md
- Monitor GitHub issues for latest updates

## 📖 Documentation

Detailed documentation is available in:
- [`sample/example.md`](IEEE-80211-8266/sample/example.md) - Complete frame examples and command reference
- [`docs/`](docs/) - Additional technical documentation
- GitHub Wiki - Installation and configuration guides

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

## 📁 Project Structure

```
IEEE-80211-8266/
├── IEEE-80211-8266.ino      # Main Arduino sketch file
├── ieee80211_structs.h      # IEEE 802.11 frame structures and definitions
├── sample/
│   └── example.md           # Detailed frame examples and documentation
├── docs/
│   └── SECURITY.md         # Security considerations and warnings
├── LICENSE                  # Educational use license
└── README.md               # Project overview and getting started
```

## 🔄 Version History

### v2.0.0 (May 21, 2025)
- Added atomic sequence number handling
- Improved frame builder error checking
- Enhanced documentation with safety warnings
- Added troubleshooting guide
- Updated command interface reference
- Added channel management strategies
- Performance optimizations

### v1.0.0 (Initial Release)
- Basic IEEE 802.11 frame construction
- Support for 4 management frame types
- Serial command interface
- Channel hopping capabilities
- Debug mode

## 🔧 Development

Project is maintained by [@stdnt-c1](https://github.com/stdnt-c1). Last updated: May 21, 2025.

To contribute or report issues:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

For bug reports or questions, please open an issue in the GitHub repository.

---
**By using this code, you agree to the above terms and accept all responsibility for its use.**

<div align="center">
  <sub>Built with ❤️ for education and research.</sub>
</div>
