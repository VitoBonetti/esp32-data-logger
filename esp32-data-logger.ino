// ----------------------------------------------------------------------------------
// Wi-Fi & GPS Data Logger for ESP32 
// ----------------------------------------------------------------------------------

// --- LIBRARIES ---
#include <WiFi.h>
#include <SD.h>
#include <SPI.h>
#include <TinyGPS++.h>
#include <esp_wifi.h> 

// --- PIN DEFINITIONS ---
#define SD_CS_PIN    5
#define SD_MOSI_PIN 23
#define SD_MISO_PIN 19
#define SD_SCK_PIN  18
#define GPS_RX_PIN 16
#define GPS_TX_PIN 17

// --- PCAP STRUCTURES DEFINED MANUALLY ---
typedef struct pcap_hdr_s {
  uint32_t magic_number;   // magic number
  uint16_t version_major;  // major version number
  uint16_t version_minor;  // minor version number
  int32_t  thiszone;       // GMT to local correction
  uint32_t sigfigs;        // accuracy of timestamps
  uint32_t snaplen;        // max length of captured packets, in octets
  uint32_t network;        // data link type
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         // timestamp seconds
  uint32_t ts_usec;        // timestamp microseconds
  uint32_t incl_len;       // number of octets of packet saved in file
  uint32_t orig_len;       // actual length of packet
} pcaprec_hdr_t;

// --- CAPTURE & TIMING SETTINGS ---
const int CAPTURE_DURATION_MINUTES = 26;
const int WAIT_DURATION_MINUTES = 5;
const unsigned long CHANNEL_HOP_INTERVAL_MS = 60 * 1000UL;
const unsigned long CAPTURE_DURATION_MS = CAPTURE_DURATION_MINUTES * 60 * 1000UL;
const unsigned long WAIT_DURATION_MS = WAIT_DURATION_MINUTES * 60 * 1000UL;
const float SD_FULL_THRESHOLD = 0.80;

// --- GLOBAL OBJECTS ---
TinyGPSPlus gps;
HardwareSerial gpsSerial(2);
File pcapFile;
String currentFilename = "";
String statusMessage = "Initializing...";
int currentCaptureChannel = 1;

// --- STATE MACHINE ---
enum State {
  GET_GPS_FIX,
  START_CAPTURE,
  CAPTURING,
  WAITING,
  SD_CARD_FULL
};
State currentState = GET_GPS_FIX;

// --- Packet Handler Callback ---
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* packet = (wifi_promiscuous_pkt_t*)buf;
  pcaprec_hdr_t pcap_rec_hdr;
  pcap_rec_hdr.ts_sec = packet->rx_ctrl.timestamp / 1000000;
  pcap_rec_hdr.ts_usec = packet->rx_ctrl.timestamp % 1000000;
  pcap_rec_hdr.incl_len = packet->rx_ctrl.sig_len;
  pcap_rec_hdr.orig_len = packet->rx_ctrl.sig_len;
  if (pcapFile) {
    pcapFile.write((uint8_t*)&pcap_rec_hdr, sizeof(pcap_rec_hdr));
    pcapFile.write((uint8_t*)packet->payload, packet->rx_ctrl.sig_len);
  }
}

// --- SETUP ---
void setup() {
  Serial.begin(115200);
  Serial.println("--- Wi-Fi Geolocation Logger Starting Up (v8) ---");
  statusMessage = "Initializing GPS...";
  gpsSerial.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
  statusMessage = "Initializing SD Card...";
  SPI.begin(SD_SCK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);
  if (!SD.begin(SD_CS_PIN)) {
    statusMessage = "Error: SD Card Mount Failed. Halting.";
    currentState = SD_CARD_FULL;
    return;
  }
  statusMessage = "Initializing Wi-Fi...";
  WiFi.mode(WIFI_AP);
  setupWebServer();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

// --- MAIN LOOP ---
void loop() {
  static unsigned long captureTimerStart = 0, channelTimerStart = 0, waitTimerStart = 0;
  String geoFilename;
  handleClient();
  while (gpsSerial.available() > 0) gps.encode(gpsSerial.read());

  switch (currentState) {
    case GET_GPS_FIX:
      statusMessage = "Waiting for GPS fix...";
      if (gps.location.isValid() && gps.date.isValid() && gps.time.isValid()) {
        Serial.println("GPS Fix Acquired!");
        currentState = START_CAPTURE;
      }
      delay(1000);
      break;

    case START_CAPTURE: {
      if (isSdCardFull()) {
        statusMessage = "SD card is full. Stopping.";
        currentState = SD_CARD_FULL;
        break;
      }
      currentFilename = generateFilename();
      geoFilename = "/WF-" + getTimestamp() + "-geo.txt";
      if (writeGeoFile(geoFilename)) {
        pcapFile = SD.open(currentFilename.c_str(), FILE_WRITE);
        if (pcapFile) {
          pcap_hdr_t file_hdr;
          file_hdr.magic_number = 0xa1b2c3d4;
          file_hdr.version_major = 2;
          file_hdr.version_minor = 4;
          file_hdr.thiszone = 0;
          file_hdr.sigfigs = 0;
          file_hdr.snaplen = 65535;
          file_hdr.network = 127; // <<< FIX IS HERE: Changed from 105 to 127 for Radiotap headers
          pcapFile.write((uint8_t*)&file_hdr, sizeof(file_hdr));
          
          Serial.println("Starting capture to " + currentFilename);
          captureTimerStart = channelTimerStart = millis();
          currentCaptureChannel = 1;
          esp_wifi_set_channel(currentCaptureChannel, WIFI_SECOND_CHAN_NONE);
          currentState = CAPTURING;
        } else {
          statusMessage = "Error opening PCAP file."; delay(5000);
        }
      } else {
        statusMessage = "Error opening GEO file."; delay(5000);
      }
      break;
    }

    case CAPTURING:
      statusMessage = "Capturing on Ch: " + String(currentCaptureChannel) + " (" + String((millis() - captureTimerStart) / 60000) + "/" + String(CAPTURE_DURATION_MINUTES) + " min)";
      if (millis() - captureTimerStart >= CAPTURE_DURATION_MS) {
        pcapFile.close();
        Serial.println("Capture finished. File saved.");
        statusMessage = "Waiting... (" + String(WAIT_DURATION_MINUTES) + " mins)";
        waitTimerStart = millis();
        currentState = WAITING;
        break;
      }
      if (millis() - channelTimerStart >= CHANNEL_HOP_INTERVAL_MS) {
        currentCaptureChannel++;
        if (currentCaptureChannel > 13) currentCaptureChannel = 1;
        esp_wifi_set_channel(currentCaptureChannel, WIFI_SECOND_CHAN_NONE);
        Serial.printf("Hopping to channel %d\n", currentCaptureChannel);
        channelTimerStart = millis();
      }
      break;

    case WAITING:
      if (millis() - waitTimerStart >= WAIT_DURATION_MS) currentState = GET_GPS_FIX;
      delay(1000);
      break;

    case SD_CARD_FULL:
      esp_wifi_set_promiscuous(false);
      statusMessage = "SD Card Full. Capture stopped.";
      delay(10000);
      break;
  }
}

// --- HELPER FUNCTIONS ---
String getTimestamp() {
  char timestamp[20];
  snprintf(timestamp, 20, "%04d%02d%02d-%02d%02d%02d", gps.date.year(), gps.date.month(), gps.date.day(), gps.time.hour(), gps.time.minute(), gps.time.second());
  return String(timestamp);
}
String generateFilename() { return "/WF-" + getTimestamp() + ".pcap"; }
bool writeGeoFile(String filename) {
  File geoFile = SD.open(filename, FILE_WRITE);
  if (geoFile) {
    geoFile.println("Capture Start Geolocation");
    geoFile.print("Latitude: "); geoFile.println(gps.location.lat(), 6);
    geoFile.print("Longitude: "); geoFile.println(gps.location.lng(), 6);
    geoFile.close();
    return true;
  }
  return false;
}
bool isSdCardFull() {
  uint64_t total = SD.totalBytes(), used = SD.usedBytes();
  if (total == 0) return true;
  return (float)used / total >= SD_FULL_THRESHOLD;
}
WiFiServer server(80);
void setupWebServer() {
  const char* ssid = "ESP32_Status_Check";
  WiFi.softAP(ssid);
  IPAddress IP = WiFi.softAPIP();
  Serial.print("AP IP address: "); Serial.println(IP);
  server.begin();
}
void handleClient() {
  WiFiClient client = server.available();
  if (client) {
    while (client.connected()) {
      if (client.available()) {
        String line = client.readStringUntil('\r');
        if (line.length() == 1 && line[0] == '\n') {
            client.println("HTTP/1.1 200 OK\nContent-type:text/html\nConnection: close\nRefresh: 10\n");
            client.println("<!DOCTYPE html><html><head><title>ESP32 Logger Status</title>");
            client.println("<meta name='viewport' content='width=device-width, initial-scale=1'>");
            client.println("<style>body{font-family: Arial, sans-serif; background-color: #282c34; color: white; text-align: center; padding: 50px;} h1{color: #61dafb;}</style>");
            client.println("</head><body><h1>ESP32 Wi-Fi Logger Status</h1>");
            client.println("<p style='font-size: 1.5em;'>Current Status: <strong>" + statusMessage + "</strong></p>");
            if (currentState == CAPTURING) client.println("<p>Last Known Location: " + String(gps.location.lat(), 6) + ", " + String(gps.location.lng(), 6) + "</p>");
            if (currentFilename != "") client.println("<p>Last/Current File: " + currentFilename + "</p>");
            client.println("</body></html>");
            break;
        }
      }
    }
    client.stop();
  }
}
