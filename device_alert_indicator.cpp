#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecureBearSSL.h>
#include <ESP8266WebServer.h>
#include <EEPROM.h>

// ---------- Pins ----------
const int redLedPin = 14;   // D5
const int greenLedPin = 12; // D6

// ---------- Timing ----------
const unsigned long wifiRetryMs = 8000;
const unsigned long alertPollMs = 5000;
const unsigned long blinkIntervalMs = 300;

// ---------- API ----------
const char* alertStateEndpoint = "/device/alerts/device-active";

// ---------- Config Storage ----------
const uint32_t CFG_MAGIC = 0x534F5331; // SOS1
const int EEPROM_SIZE = 1024;

struct DeviceConfig {
  uint32_t magic;
  char wifiSsid[33];
  char wifiPass[65];
  char backendUrl[129];
  char deviceToken[97];
};

enum LedMode {
  LED_CONNECTING,
  LED_SAFE_GREEN,
  LED_ALERT_RED_BLINK,
  LED_ERROR_RED
};

DeviceConfig cfg;
ESP8266WebServer server(80);
bool portalStarted = false;
unsigned long lastWifiTryAt = 0;
unsigned long lastAlertPollAt = 0;
unsigned long lastBlinkAt = 0;
bool blinkOn = false;
LedMode ledMode = LED_CONNECTING;

String deviceUid() {
  return "NODEMCU_" + String(ESP.getChipId(), HEX);
}

void safeCopy(char* dst, size_t dstSize, const String& src) {
  if (dstSize == 0) return;
  size_t n = src.length();
  if (n >= dstSize) n = dstSize - 1;
  memcpy(dst, src.c_str(), n);
  dst[n] = '\0';
}

void loadConfig() {
  EEPROM.begin(EEPROM_SIZE);
  EEPROM.get(0, cfg);
  if (cfg.magic != CFG_MAGIC) {
    memset(&cfg, 0, sizeof(cfg));
    cfg.magic = CFG_MAGIC;
    safeCopy(cfg.backendUrl, sizeof(cfg.backendUrl), "https://sos-backend-q0h6.onrender.com");
  }
}

void saveConfig() {
  cfg.magic = CFG_MAGIC;
  EEPROM.put(0, cfg);
  EEPROM.commit();
}

bool hasRequiredConfig() {
  return strlen(cfg.wifiSsid) > 0 && strlen(cfg.backendUrl) > 0 && strlen(cfg.deviceToken) > 0;
}

void setLeds(bool redOn, bool greenOn) {
  digitalWrite(redLedPin, redOn ? HIGH : LOW);
  digitalWrite(greenLedPin, greenOn ? HIGH : LOW);
}

void setLedMode(LedMode mode) {
  ledMode = mode;
  if (ledMode == LED_SAFE_GREEN) {
    setLeds(false, true);
  } else if (ledMode == LED_ERROR_RED) {
    setLeds(true, false);
  }
}

void updateLedAnimation() {
  unsigned long now = millis();
  if (ledMode == LED_ALERT_RED_BLINK || ledMode == LED_CONNECTING) {
    if (now - lastBlinkAt >= blinkIntervalMs) {
      lastBlinkAt = now;
      blinkOn = !blinkOn;
      if (ledMode == LED_ALERT_RED_BLINK) {
        setLeds(blinkOn, false);
      } else {
        setLeds(blinkOn, blinkOn);
      }
    }
  }
}

bool connectWifi(uint32_t timeoutMs = 20000) {
  if (WiFi.status() == WL_CONNECTED) return true;

  setLedMode(LED_CONNECTING);
  WiFi.begin(cfg.wifiSsid, cfg.wifiPass);
  Serial.print("WiFi connecting");

  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    updateLedAnimation();
    delay(60);
    Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("WiFi connected");
    Serial.print("IP: ");
    Serial.println(WiFi.localIP());
    setLedMode(LED_SAFE_GREEN);
    return true;
  }

  Serial.println("WiFi connect failed");
  setLedMode(LED_ERROR_RED);
  return false;
}

String htmlEscape(const String& s) {
  String out = s;
  out.replace("&", "&amp;");
  out.replace("<", "&lt;");
  out.replace(">", "&gt;");
  out.replace("\"", "&quot;");
  return out;
}

String buildConfigPage() {
  String uid = deviceUid();
  String ssid = htmlEscape(String(cfg.wifiSsid));
  String pass = htmlEscape(String(cfg.wifiPass));
  String backend = htmlEscape(String(cfg.backendUrl));
  String token = htmlEscape(String(cfg.deviceToken));

  String page = "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>";
  page += "<title>SOS Indicator Setup</title><style>body{font-family:Arial;padding:16px;background:#f4f6fa}";
  page += ".card{max-width:560px;margin:auto;background:#fff;padding:16px;border-radius:12px;border:1px solid #ddd}";
  page += "input{width:100%;padding:8px;margin:6px 0 12px;border:1px solid #ccc;border-radius:8px}";
  page += "button{background:#0d4f8a;color:#fff;border:0;padding:10px 14px;border-radius:8px}</style></head><body>";
  page += "<div class='card'><h2>SOS Indicator Setup</h2>";
  page += "<p><b>Device UID:</b> " + uid + "</p>";
  page += "<p>LED Logic: red blink = active device SOS, green = no device SOS.</p>";
  page += "<form method='POST' action='/save'>";
  page += "WiFi SSID<input name='wifi_ssid' value='" + ssid + "' required>";
  page += "WiFi Password<input name='wifi_pass' value='" + pass + "'>";
  page += "Backend URL<input name='backend_url' value='" + backend + "' required>";
  page += "Device Token<input name='device_token' value='" + token + "' required>";
  page += "<button type='submit'>Save & Reboot</button></form></div></body></html>";
  return page;
}

void startConfigPortal() {
  if (portalStarted) return;
  portalStarted = true;

  WiFi.mode(WIFI_AP_STA);
  String apName = "SOS-SETUP-" + String(ESP.getChipId(), HEX);
  WiFi.softAP(apName.c_str(), "12345678");

  Serial.println("SETUP MODE ENABLED");
  Serial.print("AP SSID: ");
  Serial.println(apName);
  Serial.println("Open: http://192.168.4.1");

  server.on("/", HTTP_GET, []() {
    server.send(200, "text/html", buildConfigPage());
  });

  server.on("/save", HTTP_POST, []() {
    safeCopy(cfg.wifiSsid, sizeof(cfg.wifiSsid), server.arg("wifi_ssid"));
    safeCopy(cfg.wifiPass, sizeof(cfg.wifiPass), server.arg("wifi_pass"));
    safeCopy(cfg.backendUrl, sizeof(cfg.backendUrl), server.arg("backend_url"));
    safeCopy(cfg.deviceToken, sizeof(cfg.deviceToken), server.arg("device_token"));
    saveConfig();
    server.send(200, "text/html", "<h3>Saved. Rebooting...</h3>");
    delay(800);
    ESP.restart();
  });

  server.onNotFound([]() {
    server.sendHeader("Location", "/", true);
    server.send(302, "text/plain", "");
  });

  server.begin();
  Serial.println("Setup web server started.");
}

bool responseSaysInvalidToken(int code, const String& body) {
  if (code == 400 || code == 401 || code == 403) return true;
  String b = body;
  b.toLowerCase();
  return b.indexOf("invalid device token") >= 0 ||
         b.indexOf("not linked") >= 0 ||
         b.indexOf("unknown device") >= 0;
}

bool parseHasActiveDeviceAlert(const String& body) {
  return body.indexOf("\"has_active_device_alert\":true") >= 0;
}

void pollDeviceAlertState() {
  if (!hasRequiredConfig()) return;
  if (WiFi.status() != WL_CONNECTED) return;
  if (millis() - lastAlertPollAt < alertPollMs) return;
  lastAlertPollAt = millis();

  String backend = String(cfg.backendUrl);
  backend.trim();
  if (backend.endsWith("/")) backend.remove(backend.length() - 1);
  String url = backend + String(alertStateEndpoint);

  BearSSL::WiFiClientSecure client;
  client.setInsecure();
  client.setBufferSizes(4096, 1024);

  HTTPClient http;
  http.setTimeout(12000);
  if (!http.begin(client, url)) {
    Serial.println("Alert poll HTTP begin failed");
    setLedMode(LED_ERROR_RED);
    return;
  }

  http.addHeader("Content-Type", "application/json");
  String payload = String("{\"device_uid\":\"") + deviceUid() +
                   "\",\"device_token\":\"" + String(cfg.deviceToken) + "\"}";

  int code = http.POST(payload);
  String body = http.getString();
  http.end();

  Serial.print("POST /device/alerts/device-active => ");
  Serial.println(code);

  if (code <= 0) {
    setLedMode(LED_ERROR_RED);
    return;
  }

  if (responseSaysInvalidToken(code, body)) {
    Serial.println("Token invalid or device unlinked. Open setup portal to set new token.");
    setLedMode(LED_ERROR_RED);
    return;
  }

  if (code != 200) {
    setLedMode(LED_ERROR_RED);
    return;
  }

  if (parseHasActiveDeviceAlert(body)) {
    Serial.println("Active DEVICE alert found -> RED BLINK");
    setLedMode(LED_ALERT_RED_BLINK);
  } else {
    setLedMode(LED_SAFE_GREEN);
  }
}

void setup() {
  Serial.begin(9600);
  delay(200);
  Serial.println("\nBOOT OK");
  Serial.print("Chip ID: ");
  Serial.println(String(ESP.getChipId(), HEX));
  Serial.print("Device UID: ");
  Serial.println(deviceUid());

  pinMode(redLedPin, OUTPUT);
  pinMode(greenLedPin, OUTPUT);
  setLeds(false, false);

  loadConfig();
  startConfigPortal();

  if (!hasRequiredConfig()) {
    Serial.println("Missing config. Use setup portal at http://192.168.4.1");
    setLedMode(LED_ERROR_RED);
    return;
  }

  connectWifi();
}

void loop() {
  server.handleClient();
  updateLedAnimation();

  if (WiFi.status() != WL_CONNECTED && millis() - lastWifiTryAt > wifiRetryMs) {
    lastWifiTryAt = millis();
    connectWifi(10000);
  }

  pollDeviceAlertState();
}
