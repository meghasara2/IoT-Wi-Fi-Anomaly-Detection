# ESP32 Dual-Sensor Telemetry Node & Wi-Fi Sniffer Firmware

**Target Microcontroller:** ESP32 Dev Module / NodeMCU-32S / ESP32-WROOM-32  
**Telemetry Interfaces:**
- **Wireless Wi-Fi REST API (Primary):** HTTP POST to `http://<HOST_IP>:5000/api/telemetry` over Wi-Fi
- **USB Serial (Concurrent / Fallback / Debug):** UART at **115200 baud**  
**Firmware File:** `esp32_sensor_node.ino`

---

## 1. Overview & Architecture

The ESP32 acts as an **IoT hardware sensor node and airborne threat detector**. It provides two synchronized telemetry streams to the PC host:
1. **Physical Environment Telemetry**: DHT11 Temperature & Humidity + AM312 PIR Motion.
2. **Over-the-Air 802.11 Sniffer**: Captures live wireless management attacks (Deauthentication frame subtype 12 and Disassociation frame subtype 10) floating through 2.4 GHz air space.

### Data Transmission Architecture: Wireless First
- **Wireless Wi-Fi Transmission (Primary):** The ESP32 connects directly to the Windows Mobile Hotspot (or local Wi-Fi router) and delivers telemetry wirelessly via standard HTTP REST POST requests to the host PC collector (`http://192.168.137.1:5000/api/telemetry`). No USB data tethering is required during normal operation!
- **Zero Configuration Gateway Targeting:** When connected to the Windows Mobile Hotspot, the ESP32 automatically resolves the host PC IP using `WiFi.gatewayIP()` (typically `192.168.137.1`), meaning no hardcoded host IP is necessary.
- **USB Serial (Fallback & Debug):** The firmware concurrently streams identical JSON lines over UART at 115200 baud. You can inspect live readings in the Arduino Serial Monitor or run the collector in serial/dual mode if desired.

---

## 2. Hardware Wiring & Pin Connections

| Sensor | Sensor Pin | ESP32 GPIO Pin | Description |
| :--- | :--- | :--- | :--- |
| **DHT11** | VCC (+) | **3V3** (3.3V) | Power Supply |
| **DHT11** | GND (-) | **GND** | Ground |
| **DHT11** | DATA / OUT | **GPIO 4** | 1-Wire Digital Data (Internal pullup / 4.7kΩ pullup) |
| **AM312 PIR** | VCC | **3V3** (3.3V) | Power Supply (tolerant 3.0V - 5.0V) |
| **AM312 PIR** | GND | **GND** | Ground |
| **AM312 PIR** | OUT | **GPIO 27** | Digital Output (Configured as `INPUT_PULLDOWN`) |

> **Wiring Tip**: If using bare 4-pin DHT11 sensors (without a breakout board), connect a 4.7kΩ–10kΩ pull-up resistor between the DATA pin and 3V3. Breakout boards with 3 pins already include this resistor.

---

## 3. Arduino IDE Setup & Flashing Guide

### Step 1: Install ESP32 Board Package
1. Open **Arduino IDE** (v1.8.x or v2.x).
2. Go to **File -> Preferences**.
3. In *Additional Boards Manager URLs*, add:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
4. Go to **Tools -> Board -> Boards Manager**, search for `esp32`, and install **esp32 by Espressif Systems** (version 2.0.x or 3.0.x).

### Step 2: Install Required Libraries
Open **Tools -> Manage Libraries...** and install:
1. **DHT sensor library** by Adafruit (latest version)
2. **Adafruit Unified Sensor** by Adafruit (dependency for DHT)

### Step 3: Configure Board Settings
Select the following settings under the **Tools** menu:
- **Board:** `ESP32 Dev Module` (or `NodeMCU-32S`)
- **Upload Speed:** `921600` (or `115200` if flashing fails on long cables)
- **CPU Frequency:** `240MHz (WiFi/BT)`
- **Flash Frequency:** `80MHz`
- **Flash Mode:** `QIO`
- **Port:** Select your ESP32 COM port (e.g., `COM3`, `COM6`)

### Step 4: Configure Wi-Fi Credentials & Host IP
At the top of `esp32_sensor_node.ino`, customize the Wi-Fi credentials to match your Windows Mobile Hotspot (or home router):
```cpp
#define WIFI_SSID "IoT_Network_Guard"
#define WIFI_PASSWORD "12345678"
```
- By default, `SERVER_HOST` is empty `""`, meaning the ESP32 automatically targets the Windows Mobile Hotspot default gateway (`192.168.137.1`) on port `5000`.
- If you are on a home/campus router, set `SERVER_HOST` to your host computer's local IP address (e.g., `"192.168.1.50"`).

### Step 5: Flash the Firmware
1. Open `firmware/esp32_sensor_node/esp32_sensor_node.ino`.
2. Click **Upload** (Ctrl + U).
3. If the IDE gets stuck at `Connecting........_____.....`, press and hold the **BOOT** (or **IO0**) button on your ESP32 until the flashing progress percentage appears, then release it.
4. Once flashed, the ESP32 will connect to Wi-Fi and start transmitting live readings wirelessly to the collector!

---

## 4. Telemetry Specifications

### A. Wireless Wi-Fi HTTP REST Telemetry (POST /api/telemetry)
Every ~2.0 seconds, the ESP32 sends an HTTP POST with `Content-Type: application/json` containing the environmental sensor payload:
```json
{"node":"esp32_gateway","seq":14,"uptime_ms":28120,"dht11":{"valid":1,"temp_c":24.6,"humidity":52.0},"pir":{"motion":0}}
```
The collector server immediately returns HTTP 200 `{"status":"OK","result":"SENSOR_TELEMETRY"}` and persists both Node_1 (DHT11) and Node_2 (PIR) into the database.

### B. Serial JSON Protocol (UART 115200 baud)

Communication operates over Serial at **115200 baud, 8 data bits, no parity, 1 stop bit (8N1)**.

### A. Boot Announcement
Emitted once upon ESP32 power-on / reset:
```json
{"status":"ESP32_TELEMETRY_INITIALIZED","baud":115200}
```

### B. Sensor Telemetry (every ~2.0 seconds)
Emitted periodically or on `{"cmd":"sample"}`:
```json
{"node":"esp32_gateway","seq":14,"uptime_ms":28120,"dht11":{"valid":1,"temp_c":24.6,"humidity":52.0},"pir":{"motion":0}}
```
- When DHT11 read fails, checksum fails, or reading is outside physical plausible limits (-10.0°C to 60.0°C), `"valid": 0` and `"temp_c": null, "humidity": null` are emitted.
- The AM312 PIR reports `0` (quiescent / idle) or `1` (human motion detected).

### C. Over-the-Air Wi-Fi Attack Event (subtypes 10/12)
Emitted in real time when an airborne deauthentication or disassociation frame is intercepted:
```json
{"type":"wifi_mgmt","boot_id":2489128,"seq":1,"uptime_ms":10200,"subtype":12,"reason":7,"ta":"1a:2b:3c:4d:5e:6f","da":"ff:ff:ff:ff:ff:ff","bssid":"1a:2b:3c:4d:5e:6f","rssi":-48,"is_protected":0,"wlan_seq":1042,"len":26}
```
- Subtypes: `12` = Deauthentication, `10` = Disassociation.
- Reason: 802.11 reason code (`1`-`65535`), or `null` if protected/encrypted (PMF).
- Protected: `1` if protected management frame (802.11w), `0` if raw/unprotected.
- Rate-limited onboard via FreeRTOS token-bucket (max 10 frames/sec) to protect the UART bus from saturation.

### D. Periodic Wi-Fi Management Summary (every ~1.0 second)
Emits cumulative accounting statistics:
```json
{"type":"wifi_mgmt_summary","boot_id":2489128,"summary_seq":8,"uptime_ms":8000,"window_ms":1000,"cumulative":{"rx_total":12,"tb_suppressed":0,"queue_dropped":0,"enqueued":12,"uart_accepted":12,"uart_failed":0,"malformed_rx":0,"unsupported_mgmt":140,"raw_rx":152}}
```

### E. Host Interactive Serial Commands
The firmware responds to JSON commands sent from the host across the serial line:

1. **Probe Handshake:**
   - Host sends: `{"cmd":"probe","nonce":123456}`
   - Firmware responds: `{"status":"WIFI_SNIFFER_INITIALIZED","boot_id":2489128,"nonce":123456,"channel":6}`
2. **Dynamic Channel Configuration:**
   - Host sends: `{"cmd":"set_channel","channel":11}`
   - Firmware tunes Wi-Fi radio to Channel 11 and responds: `{"status":"CHANNEL_CONFIGURED","boot_id":2489128,"channel":11}`
3. **Ping / Keepalive:**
   - Host sends: `{"cmd":"ping"}`
   - Firmware responds: `{"status":"PONG","boot_id":2489128,"uptime_ms":31200}`
4. **Force Immediate Sensor Reading:**
   - Host sends: `{"cmd":"sample"}`
   - Firmware triggers an immediate sensor read and emits the sensor JSON payload.

---

## 5. Testing with Arduino Serial Monitor

1. Set the baud rate in Serial Monitor to **115200 baud** and line ending to **Newline** (`\n`).
2. Press the **EN / RESET** button on the ESP32.
3. You should immediately see:
   ```json
   {"status":"ESP32_TELEMETRY_INITIALIZED","baud":115200}
   ```
4. Within 2 seconds, you should see periodic sensor telemetry:
   ```json
   {"node":"esp32_gateway","seq":1,"uptime_ms":2010,"dht11":{"valid":1,"temp_c":25.1,"humidity":50.2},"pir":{"motion":0}}
   ```
5. Test interactive commands by typing:
   ```json
   {"cmd":"probe","nonce":999}
   ```
   The ESP32 will immediately respond:
   ```json
   {"status":"WIFI_SNIFFER_INITIALIZED","boot_id":...,"nonce":999,"channel":6}
   ```
