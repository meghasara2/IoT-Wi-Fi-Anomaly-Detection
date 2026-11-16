# Long-Baseline Physical Capture Protocol (>= 10 Minutes Per Session)
**Target Directory**: `data/processed/experimental_time_windows/long_baseline_validation/`  
**Purpose**: Repeatable, structured protocol for capturing synchronized multi-client Wi-Fi uplink traffic and physical sensor telemetry under realistic, non-disruptive operational conditions.

---

## 1. Operational Objectives & Scientific Scope
Previous baseline experiments evaluated short traces (~70 seconds, ~102-112 one-second windows per session) across 2 mobile clients. To rigorously validate the **frozen Dual Detector** without overfitting:
- Each capture session must span **at least 10 continuous minutes (600 seconds)**.
- At least **two separate capture sessions** (Session 3 and Session 4) must be recorded on different physical runs to test cross-session generalization over extended operational intervals.
- The protocol exercises **three realistic traffic regimes** (quiescent idle, normal browsing/apps, documented non-disruptive burst) to evaluate false positive rates and timing gating.

> [!CAUTION]
> **STRICT SAFETY CONSTRAINT**: Do NOT generate malicious network traffic, floods, or denial-of-service attacks. The documented burst is purely ordinary benign traffic (e.g., loading a video stream or downloading an operating system document) to verify that normal high-rate activity does not trigger false alarms.

---

## 2. Hardware, Interface, and Client Registry

### Gateway & Capture Host
- **Host OS**: Windows 11 Laptop running Windows Mobile Hotspot (2.4 GHz, 802.11n/g).
- **Subnet**: `192.168.137.0/24` (Gateway: `192.168.137.1`).
- **Capture Tool**: Wireshark / TShark (`C:\Program Files\Wireshark\tshark.exe`).
- **Hotspot Virtual Interface**: Typically `Local Area Connection* 10` or `Local Area Connection* 9` (verify via `tshark -D`).

### Client Nodes
| Client Identifier | Client MAC Address | Assigned IP | Hardware Role | Nominal Activity |
| :--- | :--- | :--- | :--- | :--- |
| **Node_Client_1** | `ca:34:ea:92:d3:9e` | `192.168.137.201` | Primary Mobile Client | Interactive browsing, foreground app usage |
| **Node_Client_2** | `e6:2e:db:73:1c:25` | `192.168.137.6` | Secondary Mobile Client | Background telemetry, idle sync, periodic push |

### Physical Sensor Node
- **Microcontroller**: ESP32 Dev Module connected via USB to PC on serial port `COM6` at 115200 baud.
- **Sensors Attached**:
  - DHT11 Temperature & Relative Humidity (Data: GPIO 4).
  - AM312 Miniature PIR Motion Sensor (Output: GPIO 27).
- **Sampling Frequency**: JSON emitted over serial every ~2.0 seconds.
- **Listener Script**: `src/record_sensor_telemetry.py`.

---

## 3. Structured 10-Minute Activity Timeline (Per Session)

Both Session 3 and Session 4 must follow this exact minute-by-minute activity schedule:

```
[00:00] ─── (1) Quiescent Idle / Background Heartbeat (3 min) ─── [03:00]
[03:00] ─── (2) Ordinary Interactive Browsing & Apps (4 min) ─── [07:00]
[07:00] ─── (3) Documented Non-Disruptive Traffic Burst (1.5 min) ─ [08:30]
[08:30] ─── (4) Return to Quiescent Baseline / Cool Down (1.5 min) [10:00]
```

### Phase 1: Quiescent Idle / Background Heartbeat (Minutes 00:00 to 03:00)
- **Goal**: Evaluate single-packet and low-rate quiescent traffic behavior ($N < 3$ timing gating).
- **Action**: Both mobile phones remain connected to the hotspot, placed on a table, screen ON, but no foreground user interaction. Allow operating system background sync (NTP, DNS heartbeats, push notifications) to occur naturally.
- **Expected Traffic**: 1 to 5 packets/second with intermittent quiescent 1-packet intervals.

### Phase 2: Ordinary Interactive Browsing (Minutes 03:00 to 07:00)
- **Goal**: Establish nominal multi-flow interactive baseline density.
- **Action**: On `Node_Client_1`, open a web browser and browse typical news or university websites (e.g., wikipedia.org, srmist.edu.in). On `Node_Client_2`, interact with a standard mobile utility app (e.g., weather app, calendar sync).
- **Expected Traffic**: 10 to 40 packets/second, packet sizes 200–600 bytes, regular IAT pacing.

### Phase 3: Documented Non-Disruptive Traffic Burst (Minutes 07:00 to 08:30)
- **Goal**: Test model resilience against normal volumetric bursts without raising false alarms.
- **Action**: On `Node_Client_1`, stream a short standard definition or 720p/1080p web video (e.g., YouTube clip or download a 15MB technical PDF).
- **Note**: This generates high packet rates (150–500 pkts/s) with MTU-sized packets (1400–1514 bytes), allowing verification of whether the frozen detector correctly flags the burst as a primary volumetric anomaly or accommodates the burst.

### Phase 4: Quiescent Recovery (Minutes 08:30 to 10:00)
- **Goal**: Verify rapid return to baseline and lack of state-leakage or lingering detector false alarms.
- **Action**: Close the video/download, leave both phones resting on the table for the remaining 90 seconds.

---

## 4. Session Capture Run Sheet Template

For every physical run, complete the following log entry:

```markdown
### Capture Run Sheet: Session [ 3 / 4 ]
- **Session Label**: session[3/4]_10min
- **Date & Start Time (UTC)**: YYYY-MM-DD HH:MM:SS UTC
- **End Time (UTC)**: YYYY-MM-DD HH:MM:SS UTC
- **Total Duration**: 600 seconds (10 minutes)
- **Capture Interface**: Local Area Connection* [X]
- **Wireshark Capture File**: data/telemetry_test/session[3/4]_hotspot_capture.pcapng
- **Sensor Database File**: data/telemetry_test/session[3/4]_sensor_telemetry.db
- **Connected Clients Verified**:
  - Node_Client_1 (ca:34:ea:92:d3:9e, 192.168.137.201): [ YES / NO ]
  - Node_Client_2 (e6:2e:db:73:1c:25, 192.168.137.6): [ YES / NO ]
- **ESP32 COM Port**: COM6 (115200 baud)
- **Activity Log**:
  - 00:00 - 03:00: Idle background (phones resting on desk)
  - 03:00 - 07:00: Active web browsing on Node_Client_1
  - 07:00 - 08:30: 720p video streaming burst on Node_Client_1
  - 08:30 - 10:00: Idle recovery
- **Physical Sensor Notes**:
  - Room Temperature: ~____ °C
  - PIR Motion Status: [Active motion in room / Static environment]
```
