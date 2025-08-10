#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_sleep.h"
#include "esp_timer.h"
#include <SD.h>
#include "freertos/queue.h"
#include "esp_event.h"
// SD card pins (standard VSPI for ESP32)
const int SD_CS_PIN = 5;
// Scanning parameters
const unsigned long SCAN_DURATION_MS = 260000; // 4 minutes
const int HOP_INTERVAL_MS = 10000; // Time per channel
const int CHANNEL_MIN = 1;
const int CHANNEL_MAX = 13;
// PCAP structures
struct pcap_hdr_s {
    uint32_t magic_number; // 0xa1b2c3d4
    uint16_t version_major; // 2
    uint16_t version_minor; // 4
    int32_t thiszone; // 0
    uint32_t sigfigs; // 0
    uint32_t snaplen; // 65535
    uint32_t network; // 127 (LINKTYPE_IEEE802_11_RADIOTAP)
};
struct pcaprec_hdr_s {
    uint32_t ts_sec; // timestamp seconds
    uint32_t ts_usec; // timestamp microseconds
    uint32_t incl_len; // number of octets of packet saved in file
    uint32_t orig_len; // actual length of packet
};
// Packet queue to decouple callback from SD writing
struct Packet {
    wifi_pkt_rx_ctrl_t rx_ctrl;
    uint8_t payload[512]; // Assume management frames < 512 bytes
    uint32_t len;
    uint32_t ts_sec;
    uint32_t ts_usec;
};
QueueHandle_t packetQueue;
// File handle
File pcapFile;
const char* filename = "/wifi_capture2.pcap";
// Bloom filter for deduplication (reduced to 512K bits ~64KB to fit DRAM)
const size_t BLOOM_BITS = 524288;
uint8_t bloom[ BLOOM_BITS / 8 ];
// Simple FNV-like hash function
uint32_t simple_hash(const uint8_t* data, size_t len) {
    uint32_t hash = 2166136261U;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619U;
    }
    return hash;
}
// Check and add to bloom filter for duplicate check
bool is_duplicate(const uint8_t* frame, uint32_t len) {
    if (len < 24) return false; // Too short for management frame
    uint8_t subtype = frame[0] >> 4;
    const uint8_t* da = &frame[4];
    const uint8_t* sa = &frame[10];
    const uint8_t* bssid = &frame[16];
    bool has_ts = (subtype == 0x08 || subtype == 0x05); // Beacon or probe response
    uint64_t ts = 0;
    if (has_ts && len >= 32) {
        ts = *(uint64_t*)&frame[24];
    }
    // Build key: subtype + DA + SA + BSSID + TS
    uint8_t key[1 + 6 + 6 + 6 + 8];
    key[0] = subtype;
    memcpy(&key[1], da, 6);
    memcpy(&key[7], sa, 6);
    memcpy(&key[13], bssid, 6);
    memcpy(&key[19], &ts, 8);
    size_t key_len = sizeof(key);
    // Compute 3 hashes
    uint32_t h1 = simple_hash(key, key_len);
    uint32_t h2 = h1 ^ 0xDEADBEEF;
    uint32_t h3 = simple_hash((uint8_t*)&h1, sizeof(h1)) ^ simple_hash((uint8_t*)&h2, sizeof(h2));
    size_t pos1 = h1 % BLOOM_BITS;
    size_t pos2 = h2 % BLOOM_BITS;
    size_t pos3 = h3 % BLOOM_BITS;
    // Check if all bits are set
    bool all_set =
        (bloom[pos1 / 8] & (1 << (pos1 % 8))) &&
        (bloom[pos2 / 8] & (1 << (pos2 % 8))) &&
        (bloom[pos3 / 8] & (1 << (pos3 % 8)));
    // Set the bits
    bloom[pos1 / 8] |= (1 << (pos1 % 8));
    bloom[pos2 / 8] |= (1 << (pos2 % 8));
    bloom[pos3 / 8] |= (1 << (pos3 % 8));
    return all_set;
}
// Global timestamp base
int64_t start_time = 0;
// Promiscuous callback
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
    uint8_t* frame = pkt->payload;
    uint32_t len = ctrl.sig_len; // Includes FCS
    // Deduplicate
    if (is_duplicate(frame, len)) return;
    // Get relative timestamp
    int64_t now = esp_timer_get_time() - start_time;
    uint32_t ts_sec = now / 1000000LL;
    uint32_t ts_usec = now % 1000000LL;
    // Queue the packet
    Packet p;
    p.rx_ctrl = ctrl;
    p.len = len;
    p.ts_sec = ts_sec;
    p.ts_usec = ts_usec;
    if (len <= sizeof(p.payload)) {
        memcpy(p.payload, frame, len);
        xQueueSend(packetQueue, &p, 0); // No wait, drop if full
    }
}
// Function to build radiotap header
uint16_t build_radiotap(uint8_t* radiotap_buf, const wifi_pkt_rx_ctrl_t& ctrl) {
    // Rates in 0.5 Mbps units
    const uint8_t rates[] = {2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108};
    uint8_t rate;
    if (ctrl.sig_mode == 0) {
        rate = (ctrl.rate < 12) ? rates[ctrl.rate] : 0;
    } else {
        rate = 0; // For non-legacy, set to 0 for now
    }
    // Channel frequency
    uint16_t freq = 2412 + (ctrl.channel - 1) * 5;
    // Channel flags
    uint16_t chan_flags;
    if (ctrl.sig_mode == 0 && ctrl.rate <= 3) {
        chan_flags = 0x00a0; // CCK + 2GHz
    } else {
        chan_flags = 0x00c0; // OFDM + 2GHz
    }
    // Radiotap present flags: flags (1), rate (2), channel (3), antsignal (5)
    uint32_t present = (1UL << 1) | (1UL << 2) | (1UL << 3) | (1UL << 5);
    // Flags: FCS included (bit 4 = 0x10)
    uint8_t flags = 0x10;
    // Signal
    int8_t signal = ctrl.rssi;
    // Build header (little-endian)
    uint16_t rt_len = 8 + 1 + 1 + 4 + 1; // header + flags + rate + channel(4) + signal
    radiotap_buf[0] = 0; // version
    radiotap_buf[1] = 0; // pad
    radiotap_buf[2] = rt_len & 0xFF;
    radiotap_buf[3] = (rt_len >> 8) & 0xFF;
    memcpy(&radiotap_buf[4], &present, 4);
    int idx = 8;
    radiotap_buf[idx++] = flags;
    radiotap_buf[idx++] = rate;
    memcpy(&radiotap_buf[idx], &freq, 2); idx += 2;
    memcpy(&radiotap_buf[idx], &chan_flags, 2); idx += 2;
    radiotap_buf[idx++] = (uint8_t)signal;
    return rt_len;
}
void setup() {
    Serial.begin(115200);
    Serial.println("Setup started");
    // Initialize bloom filter
    memset(bloom, 0, sizeof(bloom));
    Serial.println("Bloom filter initialized");
    // Initialize SD card
    if (!SD.begin(SD_CS_PIN)) {
        Serial.println("SD card initialization failed!");
        return;
    }
    Serial.println("SD initialized OK");
    // Create or overwrite file
    if (SD.exists(filename)) SD.remove(filename);
    pcapFile = SD.open(filename, FILE_WRITE);
    if (!pcapFile) {
        Serial.println("Failed to open PCAP file!");
        return;
    }
    Serial.println("PCAP file opened");
    // Write PCAP global header
    pcap_hdr_s global_hdr = {0xa1b2c3d4, 2, 4, 0, 0, 65535, 127};
    pcapFile.write((uint8_t*)&global_hdr, sizeof(global_hdr));
    Serial.println("PCAP header written");
    // Create queue
    packetQueue = xQueueCreate(100, sizeof(Packet));
    if (!packetQueue) {
        Serial.println("Failed to create queue!");
        return;
    }
    Serial.println("Queue created");
    // Initialize event loop
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    Serial.println("Event loop created");
    // Initialize WiFi in promiscuous mode
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
    Serial.println("WiFi promiscuous mode enabled");
    // Initialize timestamp base for sniffer
    start_time = esp_timer_get_time();
    Serial.println("Timestamp base set");
}
void loop() {
    static unsigned long scan_start = millis();
    static int channel = CHANNEL_MIN;
    if (millis() - scan_start >= SCAN_DURATION_MS) {
        Serial.println("Scan duration complete, draining queue");
        // Drain remaining queue
        Packet p;
        while (xQueueReceive(packetQueue, &p, 0)) {
            // Build radiotap
            uint8_t radiotap[32]; // Max size
            uint16_t rt_len = build_radiotap(radiotap, p.rx_ctrl);
            // PCAP per-packet header
            uint32_t cap_len = rt_len + p.len;
            pcaprec_hdr_s pkt_hdr = {p.ts_sec, p.ts_usec, cap_len, cap_len};
            pcapFile.write((uint8_t*)&pkt_hdr, sizeof(pkt_hdr));
            // Write radiotap + frame
            pcapFile.write(radiotap, rt_len);
            pcapFile.write(p.payload, p.len);
        }
        // Close file and deep sleep
        pcapFile.close();
        Serial.println("File closed, entering deep sleep");
        esp_deep_sleep_start();
    }
    // Set channel
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    channel = (channel == CHANNEL_MAX) ? CHANNEL_MIN : channel + 1;
    // Hop interval
    unsigned long hop_start = millis();
    while (millis() - hop_start < HOP_INTERVAL_MS) {
        // Process queue
        Packet p;
        while (xQueueReceive(packetQueue, &p, 0)) {
            // Build radiotap
            uint8_t radiotap[32];
            uint16_t rt_len = build_radiotap(radiotap, p.rx_ctrl);
            // PCAP per-packet header
            uint32_t cap_len = rt_len + p.len;
            pcaprec_hdr_s pkt_hdr = {p.ts_sec, p.ts_usec, cap_len, cap_len};
            pcapFile.write((uint8_t*)&pkt_hdr, sizeof(pkt_hdr));
            // Write radiotap + frame
            pcapFile.write(radiotap, rt_len);
            pcapFile.write(p.payload, p.len);
        }
        delay(10); // Yield
    }
}
