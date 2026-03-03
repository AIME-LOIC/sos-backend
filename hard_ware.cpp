#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>

const char* ssid = "L4SODA&B";
const char* password = "l4sod@2026!";

// Your specific Make.com Webhook URL
const char* makeUrl = "http://jnqsf3qvs7cxjhmmhrc5p8eehgbmf5lh@hook.eu1.make.com";

const int buttonPin = 4; // This is Pin D2 on most NodeMCUs

void setup() {
  Serial.begin(115200);
  pinMode(buttonPin, INPUT_PULLUP); // Button connected to D2 and Ground
  
  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected!");
}

void loop() {
  // Detect button press (Low means the button is pressed to Ground)
  if (digitalRead(buttonPin) == LOW) {
    Serial.println("SOS Button Pressed! Sending to Make.com...");
    
    if (WiFi.status() == WL_CONNECTED) {
      WiFiClient client;
      HTTPClient http;
      
      http.begin(client, makeUrl);
      http.addHeader("Content-Type", "application/json");
      
      // We send a JSON package so Make.com knows what happened
      String jsonPayload = "{\"event\":\"SOS_TRIGGERED\", \"device\":\"V1_Hardware\", \"battery\":\"OK\"}";
      
      int httpResponseCode = http.POST(jsonPayload);
      
      if (httpResponseCode > 0) {
        Serial.print("Success! Response code: ");
        Serial.println(httpResponseCode);
      } else {
        Serial.print("Error sending POST: ");
        Serial.println(http.errorToString(httpResponseCode).c_str());
      }
      
      http.end();
    }
    
    // Cool-down period to prevent multiple alerts from one press
    delay(10000); 
  }
}