/*
  Smart Posture System Firmware (Arduino Sketch for ESP32)
  Modified with AUTO-CALIBRATION for Flex Sensors

  Hardware Configuration:
  - GPIO 34: Flex Sensor 1 (with 10kΩ resistor voltage divider)
  - GPIO 35: Flex Sensor 2 (with 10kΩ resistor voltage divider)
  - GPIO 15: Green LED (with 220Ω resistor) - Normal Posture
  - GPIO 16: Yellow LED (with 220Ω resistor) - Moderate Posture
  - GPIO 17: Red LED (with 220Ω resistor) - Critical Posture
  - GPIO 18: DC Vibration Motor Module - Critical Alert

  *** REPLACE YOUR BLYNK AND WIFI CREDENTIALS BELOW ***
*/

// --- BLYNK TEMPLATE CONFIGURATION (REQUIRED) ---
#define BLYNK_TEMPLATE_ID   "TMPL3WgTweOGW"      // <-- Replace with your actual Template ID
#define BLYNK_TEMPLATE_NAME "Scoliosis Monitor"  // <-- Replace with your actual Template Name

#include <BlynkSimpleEsp32.h>
#include <WiFi.h>

// --- USER CREDENTIALS ---
char BLYNK_AUTH_TOKEN[] = "Xz8lA_jbDKVsVmX3kvgkWhGlxfh-LrfH"; // <-- Replace with your Auth Token
char WIFI_SSID[] = "testingwifi";         // <-- Replace with your Wi-Fi SSID
char WIFI_PASS[] = "";                    // <-- Replace with your Wi-Fi Password

// --- HARDWARE PIN DEFINITIONS ---
const int FLEX_SENSOR_1_PIN = 34;  // GPIO 34 (ADC1_CH6)
const int FLEX_SENSOR_2_PIN = 35;  // GPIO 35 (ADC1_CH7)

const int LED_GREEN_PIN = 15;      // Green LED - Normal Posture
const int LED_YELLOW_PIN = 16;     // Yellow LED - Moderate Posture
const int LED_RED_PIN = 17;        // Red LED - Critical Posture

const int VIBRATION_MOTOR_PIN = 18; // DC Vibration Motor Module

// --- DYNAMIC FLEX SENSOR CALIBRATION ---
// These will be auto-updated based on your sensor readings
// Starting values - the code will adjust these automatically
int FLEX_MIN_ADC = 0;      // Minimum ADC value observed (straight position)
int FLEX_MAX_ADC = 4095;   // Maximum ADC value observed (bent position)

// Calibration mode flag
bool calibrationMode = true;
unsigned long calibrationStartTime = 0;
const unsigned long CALIBRATION_DURATION = 10000; // 10 seconds calibration

// --- COBB ANGLE THRESHOLDS ---
const int THRESHOLD_NORMAL_MAX = 10;    // Normal: 0° - 10°
const int THRESHOLD_MODERATE_MAX = 40;  // Moderate: 10° - 40°
// Critical/Severe: > 40°

// --- BLYNK VIRTUAL PINS ---
#define VPIN_STATUS_TEXT V0      // V0: Text Status
#define VPIN_ANGLE_1 V1          // V1: Gauge for Flex Sensor 1 Angle
#define VPIN_ANGLE_2 V2          // V2: Gauge for Flex Sensor 2 Angle
#define VPIN_AVG_ANGLE V3        // V3: Average Angle
#define VPIN_STATUS_LED V4       // V4: LED Widget for Status

// Timer for non-blocking task execution
BlynkTimer timer;

// --- FUNCTION: Calculate Cobb Angle from ADC Value ---
float calculateCobbAngle(int adcValue) {
  // Ensure we have valid calibration range
  if (FLEX_MAX_ADC <= FLEX_MIN_ADC) {
    return 0; // Invalid range, return 0
  }

  // Map ADC reading to angle (0 to 90 degrees)
  float angle = map(adcValue, FLEX_MIN_ADC, FLEX_MAX_ADC, 0, 90);

  // Clamp to valid range
  if (angle < 0) angle = 0;
  if (angle > 90) angle = 90;

  return angle;
}

// --- FUNCTION: Calibrate Sensors ---
void calibrateSensors() {
  if (calibrationMode) {
    // Read both sensors
    int adc1 = analogRead(FLEX_SENSOR_1_PIN);
    int adc2 = analogRead(FLEX_SENSOR_2_PIN);
    
    // Update minimum (straight position)
    if (adc1 < FLEX_MIN_ADC || FLEX_MIN_ADC == 0) FLEX_MIN_ADC = adc1;
    if (adc2 < FLEX_MIN_ADC) FLEX_MIN_ADC = adc2;
    
    // Update maximum (bent position)
    if (adc1 > FLEX_MAX_ADC || FLEX_MAX_ADC == 4095) FLEX_MAX_ADC = adc1;
    if (adc2 > FLEX_MAX_ADC) FLEX_MAX_ADC = adc2;
    
    // Check if calibration period is over
    if (millis() - calibrationStartTime >= CALIBRATION_DURATION) {
      calibrationMode = false;
      Serial.println("\n*** CALIBRATION COMPLETE ***");
      Serial.print("MIN ADC (Straight): ");
      Serial.println(FLEX_MIN_ADC);
      Serial.print("MAX ADC (Bent): ");
      Serial.println(FLEX_MAX_ADC);
      Serial.println("System is now monitoring posture...\n");
      
      // Blink all LEDs to indicate calibration complete
      for (int i = 0; i < 3; i++) {
        digitalWrite(LED_GREEN_PIN, HIGH);
        digitalWrite(LED_YELLOW_PIN, HIGH);
        digitalWrite(LED_RED_PIN, HIGH);
        delay(200);
        digitalWrite(LED_GREEN_PIN, LOW);
        digitalWrite(LED_YELLOW_PIN, LOW);
        digitalWrite(LED_RED_PIN, LOW);
        delay(200);
      }
    } else {
      // Show calibration progress
      unsigned long remaining = (CALIBRATION_DURATION - (millis() - calibrationStartTime)) / 1000;
      Serial.print("Calibrating... ");
      Serial.print(remaining);
      Serial.print("s remaining | Current range: ");
      Serial.print(FLEX_MIN_ADC);
      Serial.print(" - ");
      Serial.println(FLEX_MAX_ADC);
    }
  }
}

// --- FUNCTION: Read Sensors and Update Status ---
void sendSensorDataAndCheckPosture() {
  // Skip monitoring during calibration
  if (calibrationMode) {
    calibrateSensors();
    return;
  }

  // 1. READ BOTH FLEX SENSORS
  int flexADC1 = analogRead(FLEX_SENSOR_1_PIN);
  int flexADC2 = analogRead(FLEX_SENSOR_2_PIN);

  // 2. CALCULATE ANGLES
  float angle1 = calculateCobbAngle(flexADC1);
  float angle2 = calculateCobbAngle(flexADC2);
  
  // Calculate average angle for overall posture assessment
  float avgAngle = (angle1 + angle2) / 2.0;

  // 3. CLASSIFY POSTURE BASED ON AVERAGE ANGLE
  String postureStatus = "";

  // Reset all outputs first
  digitalWrite(LED_GREEN_PIN, LOW);
  digitalWrite(LED_YELLOW_PIN, LOW);
  digitalWrite(LED_RED_PIN, LOW);
  digitalWrite(VIBRATION_MOTOR_PIN, LOW);

  if (avgAngle <= THRESHOLD_NORMAL_MAX) {
    // NORMAL POSTURE (0° - 10°)
    postureStatus = "Normal";
    digitalWrite(LED_GREEN_PIN, HIGH);
    Blynk.setProperty(VPIN_STATUS_LED, "color", "#00FF00"); // Green
    
  } else if (avgAngle <= THRESHOLD_MODERATE_MAX) {
    // MODERATE POSTURE (10° - 40°)
    postureStatus = "Light/Moderate";
    digitalWrite(LED_YELLOW_PIN, HIGH);
    Blynk.setProperty(VPIN_STATUS_LED, "color", "#FFFF00"); // Yellow
    
  } else {
    // CRITICAL/SEVERE POSTURE (> 40°)
    postureStatus = "Critical/Severe";
    digitalWrite(LED_RED_PIN, HIGH);
    digitalWrite(VIBRATION_MOTOR_PIN, HIGH); // Activate vibration alert
    Blynk.setProperty(VPIN_STATUS_LED, "color", "#FF0000"); // Red

    // Send critical notification
    Blynk.logEvent("posture_critical", "CRITICAL POSTURE! Avg Angle: " + String(avgAngle, 1) + "°");
  }

  // 4. SEND DATA TO BLYNK
  Blynk.virtualWrite(VPIN_ANGLE_1, angle1);           // Sensor 1 angle
  Blynk.virtualWrite(VPIN_ANGLE_2, angle2);           // Sensor 2 angle
  Blynk.virtualWrite(VPIN_AVG_ANGLE, avgAngle);       // Average angle
  Blynk.virtualWrite(VPIN_STATUS_LED, 255);           // Turn status LED ON
  Blynk.virtualWrite(VPIN_STATUS_TEXT, postureStatus); // Status text

  // 5. DEBUG OUTPUT TO SERIAL MONITOR
  Serial.println("=== Posture Monitor ===");
  Serial.print("Sensor 1 - ADC: ");
  Serial.print(flexADC1);
  Serial.print(" | Angle: ");
  Serial.print(angle1, 1);
  Serial.println("°");
  
  Serial.print("Sensor 2 - ADC: ");
  Serial.print(flexADC2);
  Serial.print(" | Angle: ");
  Serial.print(angle2, 1);
  Serial.println("°");
  
  Serial.print("Average Angle: ");
  Serial.print(avgAngle, 1);
  Serial.print("° | Status: ");
  Serial.println(postureStatus);
  Serial.print("Calibration range: ");
  Serial.print(FLEX_MIN_ADC);
  Serial.print(" - ");
  Serial.println(FLEX_MAX_ADC);
  Serial.println("=======================\n");
}

// --- SETUP ---
void setup() {
  // Initialize Serial Monitor
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=================================");
  Serial.println("ESP32 Smart Posture System");
  Serial.println("2 Flex Sensors + 3 LEDs + Motor");
  Serial.println("=================================\n");

  // Initialize LED pins as outputs
  pinMode(LED_GREEN_PIN, OUTPUT);
  pinMode(LED_YELLOW_PIN, OUTPUT);
  pinMode(LED_RED_PIN, OUTPUT);
  pinMode(VIBRATION_MOTOR_PIN, OUTPUT);

  // Set initial state (all off)
  digitalWrite(LED_GREEN_PIN, LOW);
  digitalWrite(LED_YELLOW_PIN, LOW);
  digitalWrite(LED_RED_PIN, LOW);
  digitalWrite(VIBRATION_MOTOR_PIN, LOW);

  // Start calibration mode
  Serial.println("*** CALIBRATION MODE ***");
  Serial.println("Please move the flex sensors through their full range");
  Serial.println("(from straight to fully bent) for 10 seconds...\n");
  
  calibrationMode = true;
  calibrationStartTime = millis();
  FLEX_MIN_ADC = 4095;  // Start with max value
  FLEX_MAX_ADC = 0;     // Start with min value

  // Connect to Wi-Fi
  Serial.print("Connecting to Wi-Fi: ");
  Serial.println(WIFI_SSID);

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  int connectAttempts = 0;

  while (WiFi.status() != WL_CONNECTED && connectAttempts < 30) {
    delay(500);
    Serial.print(".");
    connectAttempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWi-Fi connected successfully!");
    Serial.print("IP Address: ");
    Serial.println(WiFi.localIP());
    Serial.println("Attempting to connect to Blynk...\n");

    // Connect to Blynk
    Blynk.begin(BLYNK_AUTH_TOKEN, WIFI_SSID, WIFI_PASS);

    // Set up timer to read sensors every 1 second (1000 ms)
    timer.setInterval(1000L, sendSensorDataAndCheckPosture);
    
    Serial.println("Starting calibration...\n");
  } else {
    Serial.println("\n*** FAILED TO CONNECT TO Wi-Fi ***");
    Serial.println("Please check your SSID and PASSWORD");
  }
}

// --- MAIN LOOP ---
void loop() {
  // Run Blynk and timer tasks only if connected
  if (Blynk.connected()) {
    Blynk.run();
    timer.run();
  } else {
    // If connection lost, try to reconnect
    static unsigned long lastReconnectAttempt = 0;
    if (millis() - lastReconnectAttempt > 30000) { // Try every 30 seconds
      lastReconnectAttempt = millis();
      Serial.println("Attempting to reconnect to Blynk...");
      Blynk.connect();
    }
    
    // Still run timer for calibration even without Blynk
    timer.run();
  }
}