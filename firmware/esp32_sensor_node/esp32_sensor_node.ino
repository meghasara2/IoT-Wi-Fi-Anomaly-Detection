/*
 * Firmware: ESP32 Dual-Sensor Telemetry Node with Wi-Fi Management Sniffer
 * Project: AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection
 * Target Board: ESP32 Dev Module / NodeMCU-32S
 *
 * Hardware Pin Connections:
 *   - DHT11 Data Pin:  GPIO 4 (Pull-up recommended / on module)
 *   - AM312 PIR Pin:   GPIO 27 (Digital Output)
 *   - VCC: 3.3V
 *   - GND: Common GND
 *
 * Telemetry Outputs over Serial (UART) at 115200 baud:
 *   1. Environmental Sensor Telemetry (every ~2.0s):
 *      {"node":"esp32_gateway","seq":<seq>,"uptime_ms":<millis>,"dht11":{"valid":<1|0>,"temp_c":<val|null>,"humidity":<val|null>},"pir":{"motion":<0|1>}}
 *   2. Wi-Fi Management Frame Events (Subtypes 10/12, Rate Limited to 10/s):
 *      {"type":"wifi_mgmt","boot_id":<boot_id>,"seq":<seq>,"uptime_ms":<millis>,"subtype":<10|12>,"reason":<code|null>,"ta":"<mac>","da":"<mac>","bssid":"<mac>","rssi":<rssi>,"is_protected":<0|1>,"wlan_seq":<seq>,"len":<len>}
 *   3. Wi-Fi Management Periodic Summary (every ~1.0s):
 *      {"type":"wifi_mgmt_summary","boot_id":<boot_id>,"summary_seq":<seq>,"uptime_ms":<millis>,"window_ms":<ms>,"cumulative":{...}}
 *   4. Handshake Probe Response (on receiving {"cmd":"probe","nonce":N}):
 *      {"status":"WIFI_SNIFFER_INITIALIZED","boot_id":<boot_id>,"nonce":<nonce>,"channel":<channel>}
 */

#include "DHT.h"
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "esp_system.h"
#include "esp_random.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// --- PIN DEFINITIONS ---
#define DHTPIN 4
#define DHTTYPE DHT11
#define PIRPIN 27

// --- WI-FI SNIFFER CONFIGURATION ---
// Configurable 2.4 GHz monitoring channel (default: Channel 6)
#define SNIFFER_CHANNEL 6

// Fixed queue depth for Wi-Fi management events
#define WIFI_QUEUE_DEPTH 32

// Token bucket rate limiting parameters
#define TB_CAPACITY_MILLITOKENS 10000     // 10 tokens capacity
#define TB_REFILL_RATE_PER_MS 10          // 10 millitokens/ms = 10 tokens/sec
#define TB_COST_MILLITOKENS 1000          // 1 token per admitted event

// Periodic intervals
const unsigned long SAMPLING_INTERVAL_MS = 2000;
const unsigned long WIFI_SUMMARY_INTERVAL_MS = 1000;

// --- INITIALIZE DHT SENSOR ---
DHT dht(DHTPIN, DHTTYPE);

// --- SENSOR SAMPLING PARAMETERS ---
unsigned long lastSampleTime = 0;
unsigned long sequenceNumber = 0;

// --- WI-FI SNIFFER DATA STRUCTURES ---
typedef struct {
    uint32_t seq;           // Host event admission sequence number
    uint32_t uptime_ms;     // Millis timestamp at reception
    int32_t  reason;        // 802.11 Reason Code (1-65535, or -1 for unavailable / PMF encrypted)
    int8_t   rssi;          // Received Signal Strength Indicator (dBm)
    uint8_t  subtype;       // 802.11 Management Subtype (10 = Disassoc, 12 = Deauth)
    uint8_t  is_protected;  // Protected frame flag (1 = protected/PMF, 0 = unprotected)
    uint8_t  _pad;          // Struct alignment padding
    uint16_t wlan_seq;      // 802.11 MAC Sequence Control sequence number (0-4095)
    uint16_t frame_len;     // Captured frame length (rx_ctrl.sig_len)
    uint8_t  ta[6];         // Transmitter MAC address (SA / Addr2)
    uint8_t  da[6];         // Destination MAC address (DA / Addr1)
    uint8_t  bssid[6];      // BSSID (Addr3)
    uint8_t  _pad2[2];      // 4-byte struct boundary alignment padding
} WifiMgmtEvent;

typedef struct {
    uint32_t raw_rx;
    uint32_t malformed_rx;
    uint32_t unsupported_mgmt;
    uint32_t rx_total;
    uint32_t tb_suppressed;
    uint32_t queue_dropped;
    uint32_t enqueued;
    uint32_t queue_occupancy;
    uint32_t consumer_in_flight;
    uint32_t uart_accepted;
    uint32_t uart_failed;
} AccountingSnapshot;

// --- SESSION AND ACCOUNTING STATE ---
static uint32_t s_boot_id = 0;
static uint32_t s_mgmt_seq = 0;
static uint32_t s_summary_seq = 0;
static unsigned long s_last_summary_ms = 0;

// Cumulative accounting counters (guarded strictly by s_accounting_mux)
static uint32_t s_raw_rx = 0;             // Total frames entering promiscuous callback
static uint32_t s_malformed_rx = 0;       // Frames with sig_len < 24
static uint32_t s_unsupported_mgmt = 0;   // Non-management or management subtypes other than 10 or 12
static uint32_t s_rx_total = 0;           // Total target frames (subtypes 10 or 12, sig_len >= 24)
static uint32_t s_tb_suppressed = 0;      // Target frames dropped by token bucket rate limiter
static uint32_t s_queue_dropped = 0;      // Target frames dropped due to queue buffer saturation
static uint32_t s_enqueued = 0;           // Target frames successfully admitted to the pipeline
static uint32_t s_queue_occupancy = 0;    // Number of events currently occupying or reserved in the queue
static uint32_t s_consumer_in_flight = 0; // Transient frames popped by loop() undergoing UART write
static uint32_t s_uart_accepted = 0;      // Events whose complete line was accepted by UART TX buffer
static uint32_t s_uart_failed = 0;        // Events whose UART write failed or was truncated

// Token bucket state (guarded by s_accounting_mux)
static uint32_t s_tb_millitokens = TB_CAPACITY_MILLITOKENS;
static uint32_t s_tb_last_ms = 0;

// FreeRTOS synchronization and queue handles
static QueueHandle_t s_wifi_queue = NULL;
static portMUX_TYPE s_accounting_mux = portMUX_INITIALIZER_UNLOCKED;

// Serial RX command buffer for probe handling
static char s_rx_line_buf[128];
static size_t s_rx_line_len = 0;

// Token bucket rate limiter: must be called with s_accounting_mux held
static bool token_bucket_consume(uint32_t now_ms) {
    if (s_tb_last_ms == 0) {
        s_tb_last_ms = now_ms;
    }
    uint32_t elapsed = now_ms - s_tb_last_ms;
    if (elapsed > 0) {
        uint32_t refill = elapsed * TB_REFILL_RATE_PER_MS;
        s_tb_millitokens += refill;
        if (s_tb_millitokens > TB_CAPACITY_MILLITOKENS) {
            s_tb_millitokens = TB_CAPACITY_MILLITOKENS;
        }
        s_tb_last_ms = now_ms;
    }
    if (s_tb_millitokens >= TB_COST_MILLITOKENS) {
        s_tb_millitokens -= TB_COST_MILLITOKENS;
        return true;
    }
    return false;
}

// Wi-Fi Promiscuous RX Callback
// Context: FreeRTOS Wi-Fi task context on Core 0.
// Non-blocking, zero dynamic allocations, no serial I/O.
// FreeRTOS queue APIs are strictly called OUTSIDE portENTER_CRITICAL.
void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (buf == NULL || type != WIFI_PKT_MGMT || s_wifi_queue == NULL) {
        return;
    }

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    uint16_t sig_len = pkt->rx_ctrl.sig_len;

    // 1. Minimum 802.11 management frame header length check
    if (sig_len < 24) {
        portENTER_CRITICAL(&s_accounting_mux);
        s_raw_rx++;
        s_malformed_rx++;
        portEXIT_CRITICAL(&s_accounting_mux);
        return;
    }

    const uint8_t *payload = pkt->payload;

    // 802.11 Frame Control:
    // Byte 0: bits 3:2 = Type (0 = Management), bits 7:4 = Subtype
    uint8_t fc0 = payload[0];
    uint8_t fc1 = payload[1];
    uint8_t frame_type = (fc0 >> 2) & 0x03;
    uint8_t frame_subtype = (fc0 >> 4) & 0x0F;

    // 2. Filter non-management frames or unsupported management subtypes
    if (frame_type != 0 || (frame_subtype != 10 && frame_subtype != 12)) {
        portENTER_CRITICAL(&s_accounting_mux);
        s_raw_rx++;
        s_unsupported_mgmt++;
        portEXIT_CRITICAL(&s_accounting_mux);
        return;
    }

    // 3. Target Deauthentication (12) / Disassociation (10) frame confirmed!
    WifiMgmtEvent evt;
    memset(&evt, 0, sizeof(WifiMgmtEvent));

    evt.uptime_ms = millis();
    evt.subtype = frame_subtype;
    evt.rssi = pkt->rx_ctrl.rssi;
    evt.frame_len = sig_len;

    // Extract MAC addresses from 802.11 MAC Header:
    // Addr1 (DA/RA): bytes 4-9
    memcpy(evt.da, &payload[4], 6);
    // Addr2 (SA/TA): bytes 10-15
    memcpy(evt.ta, &payload[10], 6);
    // Addr3 (BSSID): bytes 16-21
    memcpy(evt.bssid, &payload[16], 6);

    // Sequence Control (bytes 22-23):
    // Bits 3:0 = Fragment number, bits 15:4 = 12-bit sequence number (0-4095)
    uint16_t sc = (uint16_t)payload[22] | ((uint16_t)payload[23] << 8);
    evt.wlan_seq = (sc >> 4) & 0x0FFF;

    // Protected Frame Flag: Bit 6 of Frame Control byte 1 (0x40)
    evt.is_protected = (fc1 & 0x40) ? 1 : 0;

    // Reason code handling:
    // If Protected Management Frame (PMF), payload is encrypted; bytes 24-25
    // are CCMP PN0/PN1, NOT a plaintext reason code. Must set reason to -1 (null).
    if (evt.is_protected) {
        evt.reason = -1;
    } else {
        // For unprotected frames with complete reason code field (bytes 24-25)
        if (sig_len >= 26) {
            uint16_t r = (uint16_t)payload[24] | ((uint16_t)payload[25] << 8);
            if (r >= 1) {
                evt.reason = (int32_t)r;
            } else {
                evt.reason = -1;
            }
        } else {
            evt.reason = -1; // Truncated frame body
        }
    }

    // 4. Admission Control and Queue Slot Reservation
    // NOTE: Zero FreeRTOS queue APIs are called inside portENTER_CRITICAL!
    portENTER_CRITICAL(&s_accounting_mux);
    s_raw_rx++;
    s_rx_total++;

    // Token bucket rate limiter check
    if (!token_bucket_consume(evt.uptime_ms)) {
        s_tb_suppressed++;
        portEXIT_CRITICAL(&s_accounting_mux);
        return;
    }

    // Queue capacity check via tracked occupancy
    // If occupancy is at maximum depth (32), drop immediately without consuming sequence
    if (s_queue_occupancy >= WIFI_QUEUE_DEPTH) {
        s_queue_dropped++;
        portEXIT_CRITICAL(&s_accounting_mux);
        return;
    }

    // Atomically reserve queue slot and commit enqueue count BEFORE calling xQueueSend.
    // This ensures s_queue_occupancy is ALREADY >= 1 when the item becomes visible in the queue,
    // guaranteeing that a fast consumer on Core 1 CANNOT decrement s_queue_occupancy while zero!
    s_queue_occupancy++;
    s_enqueued++;
    portEXIT_CRITICAL(&s_accounting_mux);

    // 5. Non-blocking FreeRTOS queue send outside critical section
    BaseType_t ret = xQueueSend(s_wifi_queue, &evt, 0);

    // 6. Defensive rollback: only in the impossible event that xQueueSend failed
    if (ret != pdTRUE) {
        portENTER_CRITICAL(&s_accounting_mux);
        s_queue_occupancy--;
        s_enqueued--;
        s_queue_dropped++;
        portEXIT_CRITICAL(&s_accounting_mux);
    }
}

// Serial command parsing for host handshake probe
void process_command_line(const char *line) {
    if (strstr(line, "\"probe\"") != NULL && strstr(line, "\"cmd\"") != NULL) {
        const char *p = strstr(line, "\"nonce\"");
        if (p != NULL) {
            p += 7; // advance past "\"nonce\""
            while (*p == ' ' || *p == ':' || *p == '\t' || *p == '"') {
                p++;
            }
            char *endptr = NULL;
            unsigned long nonce = strtoul(p, &endptr, 10);
            if (endptr != p) {
                char resp_buf[128];
                int len = snprintf(resp_buf, sizeof(resp_buf),
                    "{\"status\":\"WIFI_SNIFFER_INITIALIZED\",\"boot_id\":%lu,\"nonce\":%lu,\"channel\":%d}\n",
                    (unsigned long)s_boot_id, nonce, SNIFFER_CHANNEL);
                if (len > 0 && len < (int)sizeof(resp_buf)) {
                    Serial.write((const uint8_t*)resp_buf, (size_t)len);
                }
            }
        }
    }
}

// Non-blocking serial input reader
void handle_serial_input() {
    while (Serial.available() > 0) {
        char c = (char)Serial.read();
        if (c == '\n' || c == '\r') {
            if (s_rx_line_len > 0) {
                s_rx_line_buf[s_rx_line_len] = '\0';
                process_command_line(s_rx_line_buf);
                s_rx_line_len = 0;
            }
        } else if (s_rx_line_len < sizeof(s_rx_line_buf) - 1) {
            s_rx_line_buf[s_rx_line_len++] = c;
        } else {
            // Line too long: discard to prevent buffer overrun
            s_rx_line_len = 0;
        }
    }
}

// Format and transmit individual Wi-Fi management event
// Returns true ONLY if the entire serialized line was accepted by the UART TX buffer.
// Called without holding s_accounting_mux to avoid blocking other tasks during serial I/O.
bool emit_wifi_mgmt_event(const WifiMgmtEvent *evt) {
    char buf[320];
    char reason_str[16];
    if (evt->reason >= 1 && evt->reason <= 65535) {
        snprintf(reason_str, sizeof(reason_str), "%ld", (long)evt->reason);
    } else {
        snprintf(reason_str, sizeof(reason_str), "null");
    }

    int len = snprintf(buf, sizeof(buf),
        "{\"type\":\"wifi_mgmt\",\"boot_id\":%lu,\"seq\":%lu,\"uptime_ms\":%lu,"
        "\"subtype\":%u,\"reason\":%s,"
        "\"ta\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
        "\"da\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
        "\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
        "\"rssi\":%d,\"is_protected\":%u,\"wlan_seq\":%u,\"len\":%u}\n",
        (unsigned long)s_boot_id,
        (unsigned long)evt->seq,
        (unsigned long)evt->uptime_ms,
        (unsigned int)evt->subtype,
        reason_str,
        evt->ta[0], evt->ta[1], evt->ta[2], evt->ta[3], evt->ta[4], evt->ta[5],
        evt->da[0], evt->da[1], evt->da[2], evt->da[3], evt->da[4], evt->da[5],
        evt->bssid[0], evt->bssid[1], evt->bssid[2], evt->bssid[3], evt->bssid[4], evt->bssid[5],
        (int)evt->rssi,
        (unsigned int)evt->is_protected,
        (unsigned int)evt->wlan_seq,
        (unsigned int)evt->frame_len
    );

    if (len > 0 && len < (int)sizeof(buf)) {
        size_t written = Serial.write((const uint8_t*)buf, (size_t)len);
        return (written == (size_t)len);
    }
    return false;
}

// Format and transmit periodic Wi-Fi management summary
// Takes atomic snapshot of all counters under critical section, then formats/transmits outside lock.
void emit_wifi_mgmt_summary(unsigned long now_ms) {
    AccountingSnapshot snap;
    uint32_t current_summary_seq = 0;
    portENTER_CRITICAL(&s_accounting_mux);
    snap.raw_rx = s_raw_rx;
    snap.malformed_rx = s_malformed_rx;
    snap.unsupported_mgmt = s_unsupported_mgmt;
    snap.rx_total = s_rx_total;
    snap.tb_suppressed = s_tb_suppressed;
    snap.queue_dropped = s_queue_dropped;
    snap.enqueued = s_enqueued;
    snap.queue_occupancy = s_queue_occupancy;
    snap.consumer_in_flight = s_consumer_in_flight;
    snap.uart_accepted = s_uart_accepted;
    snap.uart_failed = s_uart_failed;
    s_summary_seq++;
    current_summary_seq = s_summary_seq;
    portEXIT_CRITICAL(&s_accounting_mux);

    unsigned long window_ms = (s_last_summary_ms == 0) ? 1000 : (now_ms - s_last_summary_ms);
    s_last_summary_ms = now_ms;

    char buf[384];
    int len = snprintf(buf, sizeof(buf),
        "{\"type\":\"wifi_mgmt_summary\",\"boot_id\":%lu,\"summary_seq\":%lu,"
        "\"uptime_ms\":%lu,\"window_ms\":%lu,\"cumulative\":{"
        "\"rx_total\":%lu,\"tb_suppressed\":%lu,\"queue_dropped\":%lu,"
        "\"enqueued\":%lu,\"uart_accepted\":%lu,\"uart_failed\":%lu,"
        "\"malformed_rx\":%lu,\"unsupported_mgmt\":%lu,\"raw_rx\":%lu}}\n",
        (unsigned long)s_boot_id,
        (unsigned long)current_summary_seq,
        (unsigned long)now_ms,
        (unsigned long)window_ms,
        (unsigned long)snap.rx_total,
        (unsigned long)snap.tb_suppressed,
        (unsigned long)snap.queue_dropped,
        (unsigned long)snap.enqueued,
        (unsigned long)snap.uart_accepted,
        (unsigned long)snap.uart_failed,
        (unsigned long)snap.malformed_rx,
        (unsigned long)snap.unsupported_mgmt,
        (unsigned long)snap.raw_rx
    );

    if (len > 0 && len < (int)sizeof(buf)) {
        Serial.write((const uint8_t*)buf, (size_t)len);
    }
}

// Initialize Wi-Fi promiscuous reception
void init_wifi_sniffer() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_channel(SNIFFER_CHANNEL, WIFI_SECOND_CHAN_NONE);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);
    esp_wifi_set_promiscuous(true);
}

void setup() {
  // Initialize Serial interface at 115200 baud
  Serial.begin(115200);

  // Initialize GPIO pins
  pinMode(PIRPIN, INPUT);

  // Initialize DHT11 sensor
  dht.begin();

  // Allow hardware power & sensors to stabilize
  delay(1000);

  // Emit startup announcement as a comment or info line (matches existing)
  Serial.println("{\"status\":\"ESP32_TELEMETRY_INITIALIZED\",\"baud\":115200}");

  // Generate unique 32-bit boot session ID using hardware RNG
  s_boot_id = esp_random();
  while (s_boot_id == 0) {
    s_boot_id = esp_random();
  }

  // Create FreeRTOS queue for Wi-Fi management events
  s_wifi_queue = xQueueCreate(WIFI_QUEUE_DEPTH, sizeof(WifiMgmtEvent));

  // Initialize Wi-Fi sniffer in promiscuous mode
  init_wifi_sniffer();

  s_last_summary_ms = millis();
}

void loop() {
  unsigned long currentMillis = millis();

  // 1. Process serial commands (e.g. handshake probe)
  handle_serial_input();

  // 2. Drain and transmit enqueued Wi-Fi management events (up to 8 per loop)
  if (s_wifi_queue != NULL) {
    WifiMgmtEvent evt;
    int drained = 0;
    while (drained < 8 && xQueueReceive(s_wifi_queue, &evt, 0) == pdTRUE) {
      // Transition from queue occupancy to consumer in flight
      portENTER_CRITICAL(&s_accounting_mux);
      s_queue_occupancy--;
      s_consumer_in_flight++;
      // Assign monotonic host sequence number upon verified queue dequeue
      evt.seq = ++s_mgmt_seq;
      portEXIT_CRITICAL(&s_accounting_mux);

      // Format JSON and write over UART (NO spinlock held during UART operations)
      bool write_ok = emit_wifi_mgmt_event(&evt);

      // Commit UART outcome atomically
      portENTER_CRITICAL(&s_accounting_mux);
      s_consumer_in_flight--;
      if (write_ok) {
        s_uart_accepted++;
      } else {
        s_uart_failed++;
      }
      portEXIT_CRITICAL(&s_accounting_mux);

      drained++;
    }
  }

  // 3. Emit periodic Wi-Fi management summary telemetry (every 1000 ms)
  if (currentMillis - s_last_summary_ms >= WIFI_SUMMARY_INTERVAL_MS) {
    emit_wifi_mgmt_summary(currentMillis);
  }

  // 4. Non-blocking sampling timer every SAMPLING_INTERVAL_MS (2000 ms)
  if (currentMillis - lastSampleTime >= SAMPLING_INTERVAL_MS) {
    lastSampleTime = currentMillis;
    sequenceNumber++;

    // 1. Read DHT11 Temperature and Humidity
    float humidity = dht.readHumidity();
    float temperature = dht.readTemperature(); // Celsius

    // 2. Validate DHT11 sensor readings (isnan check)
    bool dhtValid = !isnan(humidity) && !isnan(temperature);

    // 3. Read AM312 PIR Motion Sensor (Digital 0 or 1)
    int pirMotion = digitalRead(PIRPIN);

    // 4. Construct and emit clean, single-line JSON payload
    // If DHT11 read timed out or failed checksum, emit 'null' rather than artificial '0.0'
    Serial.print("{\"node\":\"esp32_gateway\",\"seq\":");
    Serial.print(sequenceNumber);
    Serial.print(",\"uptime_ms\":");
    Serial.print(currentMillis);

    Serial.print(",\"dht11\":{\"valid\":");
    Serial.print(dhtValid ? 1 : 0);
    Serial.print(",\"temp_c\":");
    if (dhtValid) {
      Serial.print(temperature, 1);
    } else {
      Serial.print("null");
    }
    Serial.print(",\"humidity\":");
    if (dhtValid) {
      Serial.print(humidity, 1);
    } else {
      Serial.print("null");
    }
    Serial.print("}");

    Serial.print(",\"pir\":{\"motion\":");
    Serial.print(pirMotion);
    Serial.println("}}");
  }
}
