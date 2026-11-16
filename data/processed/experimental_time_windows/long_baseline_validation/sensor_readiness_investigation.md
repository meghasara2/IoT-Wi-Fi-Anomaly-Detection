# Physical Sensor Hardware Readiness Investigation
**Target File**: `data/processed/experimental_time_windows/long_baseline_validation/sensor_readiness_investigation.md`  
**Scope**: Read-only engineering analysis of ESP32 sensor node hardware (`firmware/esp32_sensor_node/esp32_sensor_node.ino`) and empirical capture databases (`data/telemetry_test/`).

---

## 1. Executive Summary & Readiness Status

> [!WARNING]
> **SENSOR READINESS NOTICE**: The attached physical sensors (AM312 PIR and DHT11) are **NOT fully reliable** and exhibit known hardware-level failure modes. They have **NOT** been physically recalibrated or modified in firmware. Do **NOT** assume the sensors are defect-free or use their output to infer cybersecurity ground truth.

Physical sensor telemetry serves solely as **environmental context** (nearest-neighbor correlation within $\pm 2.0$ seconds). Network anomaly scoring models (Primary, Timing, and Dual Combined) are based strictly on layer-2/3/4 packet timing and size statistics and **never consume sensor features**.

---

## 2. AM312 PIR Motion Sensor Investigation

### Firmware Configuration:
- **Sensor**: AM312 Passive Infrared Pyroelectric Sensor.
- **Pin**: GPIO 27 (`#define PIRPIN 27`, `pinMode(PIRPIN, INPUT)`).
- **Read Logic**: `int pirMotion = digitalRead(PIRPIN)`.
- **Emitted JSON**: `{"pir":{"motion": 0 | 1}}`.

### Empirical Database Findings:
Analyzing historical recordings in `data/telemetry_test/`:
1. **Session 1 (`synchronized_sensor_telemetry.db`)**:
   - Total samples: 35.
   - Motion detected = 0: 14 samples (40.0%).
   - Motion detected = 1: 21 samples (60.0%).
   - Behavior: Demonstrated dynamic state transitions between motion and rest.
2. **Session 2 (`synchronized2_sensor_telemetry.db`)**:
   - Total samples: 35.
   - Motion detected = 0: **0 samples (0.0%)**.
   - Motion detected = 1: **35 samples (100.0%)** (STUCK HIGH).

### Root Cause Analysis (Without Firmware Changes):
The AM312 sensor stayed continuously HIGH in Session 2 due to one or more known hardware constraints:
1. **Absence of Internal Pull-Down Resistor**: GPIO 27 was configured as `pinMode(PIRPIN, INPUT)` without enabling `INPUT_PULLDOWN`. High-impedance CMOS floating lines on ESP32 can latch HIGH if the AM312 module's open-drain or weak-push-pull output remains elevated.
2. **Re-trigger Latch & Lockout Timing**: The AM312 has a fixed internal non-retriggerable/re-triggerable lockout delay (~2.3 to 8.0 seconds depending on RC components). If human movement or thermal drafts remain within its 100-degree detection cone, output remains latched HIGH throughout a short 70-second capture.
3. **Power-On Settling Time**: AM312 requires up to 15–30 seconds after cold boot to stabilize its infrared background baseline. If capture starts immediately after plugging in USB, initial samples will read continuous false-positive motion.

---

## 3. DHT11 Temperature & Humidity Sensor Reliability Investigation

### Firmware Configuration:
- **Sensor**: DHT11 Single-Bus Digital Humidity & Temperature.
- **Pin**: GPIO 4 (`#define DHTPIN 4`, `#define DHTTYPE DHT11`).
- **Read Logic**:
  ```cpp
  float humidity = dht.readHumidity();
  float temperature = dht.readTemperature();
  bool dhtValid = !isnan(humidity) && !isnan(temperature);
  ```
- **Null Safety**: If checksum fails or read times out, firmware correctly emits `"temp_c": null, "humidity": null, "valid": 0`.

### Empirical Database Findings:
1. **Session 1 (`synchronized_sensor_telemetry.db`)**:
   - Total samples: 35.
   - Valid reads (`dht_valid = 1`): 35 (100.0%).
   - Invalid reads (`dht_valid = 0`): 0 (0.0%).
2. **Session 2 (`synchronized2_sensor_telemetry.db`)**:
   - Total samples: 35.
   - Valid reads (`dht_valid = 1`): 30 (85.7%).
   - Invalid / Timed out reads (`dht_valid = 0`): **5 reads (14.3%)** (NULL temperature/humidity).

### Root Cause Analysis:
1. **1-Wire Timing Sensitivity**: The DHT11 uses a proprietary bit-banging protocol where bits are encoded as $26\text{–}28\,\mu\text{s}$ (logical 0) vs $70\,\mu\text{s}$ (logical 1) pulses. Any ESP32 FreeRTOS background interrupt or Wi-Fi stack activity can interrupt microsecond pulse measurements, triggering checksum failure (`isnan`).
2. **2.0-Second Minimum Polling Interval**: The DHT11 has a maximum response frequency of 0.5 Hz (requires at least 2.0 seconds between reads). In `esp32_sensor_node.ino`, sampling occurs every `2000 ms`. Polling exactly at the hardware limit leads to intermittent read collisions and missed handshakes.
3. **Database Null-Safety Verification**: The storage script ([`src/record_sensor_telemetry.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/record_sensor_telemetry.py)) and alignment script ([`src/align_time_windows_with_sensors.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/align_time_windows_with_sensors.py)) gracefully handle failed reads by persisting SQL `NULL` and pandas `NaN`. They never substitute fake values (such as `0.0°C` or artificial room defaults).

---

## 4. Operational Recommendations for New Captures
1. **Do NOT Treat Sensor Telemetry as Attack Signals**: If temperature rises or PIR motion remains HIGH, this represents ambient physical environment or sensor quirk, NOT network intrusion.
2. **Allow 30 Seconds Pre-Warm Time**: When connecting ESP32 to USB on COM6, allow the board and sensors to run for at least 30 seconds before starting the TShark network capture to allow the AM312 pyroelectric baseline to settle.
3. **Document Sensor Status in Run Sheets**: Record whether physical personnel were moving in the room to facilitate accurate contextual evaluation during subsequent data inspection.
