#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecure.h>

// ---------------- CONFIG ----------------
const char* ssid = "PUT_WIFI_SSID";
const char* password = "PUT_WIFI_PASSWORD";

const char* backendBaseUrl = "https://sos-backend-q0h6.onrender.com";
const char* deviceSosEndpoint = "/device/sos";

// Get this from app after linking device UID.
String deviceToken = "PUT_DEVICE_TOKEN_HERE";

// Hardware pins
const int buttonPin = 4; // D2 on NodeMCU

// Demo coordinates (replace with GPS sensor values if available)
const float fallbackLat = -1.9441;
const float fallbackLon = 30.0619;

// ---------------- HELPERS ----------------
String deviceUid() {
  return "NODEMCU_" + String(ESP.getChipId(), HEX);
}

void ensureWifi() {
  if (WiFi.status() == WL_CONNECTED) return;
  WiFi.begin(ssid, password);
  Serial.print("WiFi connecting");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
}

bool sendSOS(float lat, float lon) {
  if (deviceToken.length() == 0 || deviceToken == "PUT_DEVICE_TOKEN_HERE") {
    Serial.println("Missing device token. Link device in app first.");
    return false;
  }

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  String url = String(backendBaseUrl) + String(deviceSosEndpoint);

  if (!http.begin(client, url)) {
    Serial.println("HTTP begin failed");
    return false;
  }

  http.addHeader("Content-Type", "application/json");
  String payload = String("{\"device_uid\":\"") + deviceUid() +
                   "\",\"device_token\":\"" + deviceToken +
                   "\",\"latitude\":" + String(lat, 6) +
                   ",\"longitude\":" + String(lon, 6) + "}";

  int code = http.POST(payload);
  String body = http.getString();
  http.end();

  Serial.print("POST /device/sos => ");
  Serial.println(code);
  Serial.println(body);
  return code >= 200 && code < 300;
}

// ---------------- ARDUINO ----------------
void setup() {
  Serial.begin(9600); // Easier serial monitor compatibility
  delay(200);
  Serial.println("\nBOOT OK");

  pinMode(buttonPin, INPUT_PULLUP);
  ensureWifi();

  Serial.print("Device UID: ");
  Serial.println(deviceUid());
  Serial.println("Link this UID in app, then set deviceToken and re-upload.");
}

void loop() {
  ensureWifi();

  if (digitalRead(buttonPin) == LOW) {
    Serial.println("Button pressed -> sending SOS...");
    bool ok = sendSOS(fallbackLat, fallbackLon);
    if (ok) Serial.println("SOS sent");
    else Serial.println("SOS failed");

    // Cooldown/debounce
    delay(10000);
  }

  delay(60);
}
