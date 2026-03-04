#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecureBearSSL.h>
#include <ESP8266WebServer.h>
#include <EEPROM.h>

// ---------- Device Behavior ----------
const int buttonPin = 4; // D2 (GPIO4), INPUT_PULLUP, pressed = LOW
const unsigned long debounceMs = 60;
const unsigned long wifiRetryMs = 8000;

// Demo coordinates (replace with GPS integration)
const float fallbackLat = -1.9441;
const float fallbackLon = 30.0619;
const char* sosEndpoint = "/device/sos";

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

DeviceConfig cfg;
ESP8266WebServer server(80);
bool portalStarted = false;

int lastReading = HIGH;
int stableState = HIGH;
unsigned long lastEdgeAt = 0;
unsigned long lastWifiTryAt = 0;

String deviceUid() {
  return "NODEMCU_" + String(ESP.getChipId(), HEX);
}

String backendHostFromUrl() {
  String s = String(cfg.backendUrl);
  s.trim();
  if (s.startsWith("https://")) s = s.substring(8);
  if (s.startsWith("http://")) s = s.substring(7);
  int slash = s.indexOf('/');
  if (slash >= 0) s = s.substring(0, slash);
  int colon = s.indexOf(':');
  if (colon >= 0) s = s.substring(0, colon);
  return s;
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

void clearDeviceTokenAndWait() {
  safeCopy(cfg.deviceToken, sizeof(cfg.deviceToken), "");
  saveConfig();
  Serial.println("Local token cleared. Device is now waiting to be connected.");
}

bool shouldClearTokenOnResponse(int code, const String& body) {
  if (code == 400 || code == 401 || code == 403) return true;
  String b = body;
  b.toLowerCase();
  return b.indexOf("invalid device token") >= 0 ||
         b.indexOf("not linked") >= 0 ||
         b.indexOf("unknown device") >= 0 ||
         b.indexOf("unlinked") >= 0;
}

bool hasRequiredConfig() {
  return strlen(cfg.wifiSsid) > 0 && strlen(cfg.backendUrl) > 0 && strlen(cfg.deviceToken) > 0;
}

bool connectWifi(uint32_t timeoutMs = 20000) {
  if (WiFi.status() == WL_CONNECTED) return true;

  WiFi.begin(cfg.wifiSsid, cfg.wifiPass);
  Serial.print("WiFi connecting");

  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(400);
    Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("WiFi connected");
    Serial.print("IP: ");
    Serial.println(WiFi.localIP());
    return true;
  }
  Serial.println("WiFi connect failed");
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
  page += "<title>SOS Device Setup</title><style>body{font-family:Arial;padding:16px;background:#f4f6fa}";
  page += ".card{max-width:520px;margin:auto;background:#fff;padding:16px;border-radius:12px;border:1px solid #ddd}";
  page += "input{width:100%;padding:8px;margin:6px 0 12px;border:1px solid #ccc;border-radius:8px}";
  page += "button{background:#0d4f8a;color:#fff;border:0;padding:10px 14px;border-radius:8px}</style></head><body>";
  page += "<div class='card'><h2>SOS Device Setup</h2>";
  page += "<p><b>Device UID:</b> " + uid + "</p>";
  page += "<form method='POST' action='/save'>";
  page += "WiFi SSID<input name='wifi_ssid' value='" + ssid + "' required>";
  page += "WiFi Password<input name='wifi_pass' value='" + pass + "'>";
  page += "Backend URL<input name='backend_url' value='" + backend + "' required>";
  page += "Device Token<input name='device_token' value='" + token + "' required>";
  page += "<button type='submit'>Save & Reboot</button></form>";
  page += "<p>After saving, reopen app and test SOS button.</p></div></body></html>";
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

bool sendSOS(float lat, float lon) {
  if (strlen(cfg.deviceToken) == 0) {
    Serial.println("Missing device token. Open setup portal.");
    return false;
  }

  // Reduce RAM pressure for TLS by temporarily switching from AP+STA to STA.
  WiFiMode_t prevMode = WiFi.getMode();
  bool hadAp = (prevMode == WIFI_AP || prevMode == WIFI_AP_STA);
  String apName = "SOS-SETUP-" + String(ESP.getChipId(), HEX);
  if (hadAp) {
    server.stop();
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
    delay(200);
  }

  if (WiFi.status() != WL_CONNECTED) {
    // Reconnect in pure STA mode for a cleaner TLS path.
    WiFi.begin(cfg.wifiSsid, cfg.wifiPass);
    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 8000) {
      delay(200);
    }
  }

  Serial.print("Free heap before HTTPS: ");
  Serial.println(ESP.getFreeHeap());

  String backend = String(cfg.backendUrl);
  backend.trim();
  if (backend.endsWith("/")) backend.remove(backend.length() - 1);

  BearSSL::WiFiClientSecure client;
  client.setInsecure();
  // Render TLS can fail with very small buffers on ESP8266.
  client.setBufferSizes(4096, 1024);
  HTTPClient http;
  http.setTimeout(15000);

  String url = backend + String(sosEndpoint);
  if (!http.begin(client, url)) {
    Serial.println("HTTP begin failed");
    if (hadAp) {
      WiFi.mode(WIFI_AP_STA);
      WiFi.softAP(apName.c_str(), "12345678");
      server.begin();
    }
    return false;
  }

  http.addHeader("Content-Type", "application/json");
  String payload = String("{\"device_uid\":\"") + deviceUid() +
                   "\",\"device_token\":\"" + String(cfg.deviceToken) +
                   "\",\"latitude\":" + String(lat, 6) +
                   ",\"longitude\":" + String(lon, 6) + "}";

  int code = http.POST(payload);
  String body = http.getString();
  if (code <= 0) {
    Serial.print("HTTP error: ");
    Serial.println(http.errorToString(code).c_str());
  }
  http.end();

  // Restore AP portal
  if (hadAp) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP(apName.c_str(), "12345678");
    server.begin();
  }

  Serial.print("POST /device/sos => ");
  Serial.println(code);
  Serial.println(body);

  // If backend says token/link invalid, clear token locally and wait for re-link.
  if (shouldClearTokenOnResponse(code, body)) {
    Serial.println("Device token is invalid or device is unlinked.");
    clearDeviceTokenAndWait();
  }

  return code >= 200 && code < 300;
}

void printNetworkDebug() {
  Serial.print("WiFi.status=");
  Serial.println((int)WiFi.status());
  Serial.print("STA IP=");
  Serial.println(WiFi.localIP());
  Serial.print("Gateway=");
  Serial.println(WiFi.gatewayIP());
  Serial.print("DNS=");
  Serial.println(WiFi.dnsIP());

  String host = backendHostFromUrl();
  Serial.print("Backend host=");
  Serial.println(host);

  IPAddress resolved;
  bool dnsOk = WiFi.hostByName(host.c_str(), resolved);
  Serial.print("DNS resolve: ");
  if (dnsOk) {
    Serial.print("OK -> ");
    Serial.println(resolved);
  } else {
    Serial.println("FAILED");
  }

  WiFiClient tcpClient;
  bool tcpOk = tcpClient.connect(host.c_str(), 443);
  Serial.print("TCP connect 443: ");
  Serial.println(tcpOk ? "OK" : "FAILED");
  if (tcpOk) tcpClient.stop();

  BearSSL::WiFiClientSecure tlsClient;
  tlsClient.setInsecure();
  tlsClient.setBufferSizes(4096, 1024);
  bool tlsOk = tlsClient.connect(host.c_str(), 443);
  Serial.print("TLS connect 443: ");
  Serial.println(tlsOk ? "OK" : "FAILED");
  if (tlsOk) tlsClient.stop();
}

void setup() {
  Serial.begin(9600);
  delay(200);
  Serial.println("\nBOOT OK");
  Serial.print("Reset reason: ");
  Serial.println(ESP.getResetReason());
  Serial.print("Chip ID: ");
  Serial.println(String(ESP.getChipId(), HEX));
  Serial.print("Device UID: ");
  Serial.println(deviceUid());

  pinMode(buttonPin, INPUT_PULLUP);
  loadConfig();

  // Always keep setup AP+portal available.
  WiFi.mode(WIFI_AP_STA);
  startConfigPortal();

  // Hold button during boot only to indicate setup mode preference in logs.
  if (digitalRead(buttonPin) == LOW) {
    Serial.println("Boot button held: setup portal already active (AP+STA).");
  }

  if (!hasRequiredConfig()) {
    Serial.println("Missing config. Use setup portal at http://192.168.4.1");
    return;
  }

  if (!connectWifi()) {
    Serial.println("WiFi failed. Setup portal still available at http://192.168.4.1");
    return;
  }

  Serial.println("Device ready.");
}

void loop() {
  // Always serve setup page in AP mode while device runs normally.
  server.handleClient();

  if (WiFi.status() != WL_CONNECTED && millis() - lastWifiTryAt > wifiRetryMs) {
    lastWifiTryAt = millis();
    connectWifi(8000);
  }

  int reading = digitalRead(buttonPin);
  if (reading != lastReading) {
    lastEdgeAt = millis();
    lastReading = reading;
  }

  if ((millis() - lastEdgeAt) > debounceMs && stableState != reading) {
    stableState = reading;
    if (stableState == LOW) {
      Serial.println("BUTTON PRESSED -> sending SOS...");
      printNetworkDebug();
      bool ok = sendSOS(fallbackLat, fallbackLon);
      Serial.println(ok ? "SOS sent" : "SOS failed");
    } else {
      Serial.println("BUTTON RELEASED");
    }
  }

  static unsigned long lastBeat = 0;
  if (millis() - lastBeat > 3000) {
    lastBeat = millis();
    Serial.print("Heartbeat | wifi=");
    Serial.print(WiFi.status() == WL_CONNECTED ? "connected" : "disconnected");
    Serial.print(" | button=");
    Serial.println(stableState == LOW ? "LOW(pressed)" : "HIGH(released)");
  }
}
