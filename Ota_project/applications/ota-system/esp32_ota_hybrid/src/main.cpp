#include <Arduino.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <Update.h>
#include <WiFi.h>
#include <esp_heap_caps.h>
#include <bootloader_random.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <mbedtls/gcm.h>
#include <stdlib.h>
#include <string.h>
#ifdef JOURNAL_DEVICE_STRESS
#include "journal_stress.h"
#endif

extern "C" {
#include "mlkem_native/kem.h"
#include "XMSS_params.h"
#include "XMSS_xmss.h"
#include "XMSS_sha256.h"
#include "xmss_trusted_key.h"
}

#if __has_include("network_config.local.h")
#include "network_config.local.h"
#else
#include "network_config.example.h"
#endif
static const unsigned int DIAGNOSTIC_BUILD = 3;
static const unsigned long POLL_INTERVAL_MS = 1000UL;
static const size_t MAX_FIRMWARE_BYTES = 1900000U;
static const size_t MLKEM_CIPHERTEXT_BYTES = MLKEM_INDCCA_CIPHERTEXTBYTES;
static const size_t AES_GCM_NONCE_BYTES = 12U;
static const size_t AES_GCM_TAG_BYTES = 16U;
static unsigned long last_poll_ms = 0;
static unsigned int current_version;
static char device_id[13];
static char current_update_id[40] = "";
static bool has_connected_once = false;
static bool ota_in_progress = false;
static uint32_t wifi_reconnect_attempts = 0;
static uint32_t wifi_offline_since_ms = 0;
static uint64_t wifi_total_offline_ms = 0;
static uint32_t http_request_count = 0;
static uint32_t http_failure_count = 0;
static int last_http_status = 0;
static uint32_t last_http_latency_ms = 0;
static uint32_t ota_started_ms = 0;
static uint32_t ota_download_ms = 0;
static size_t ota_download_bytes = 0;
static uint32_t ota_install_ms = 0;
static uint32_t ota_total_ms = 0;
static const char *boot_reset_reason;
static unsigned char xmss_signed_message[XMSS_SIG_BYTES + SHA256_BLOCK_SIZE];
static unsigned char xmss_recovered_message[XMSS_SIG_BYTES + SHA256_BLOCK_SIZE];
static uint8_t mlkem_public_key[MLKEM_INDCCA_PUBLICKEYBYTES];
static uint8_t mlkem_secret_key[MLKEM_INDCCA_SECRETKEYBYTES];

static const char *reset_reason_name(esp_reset_reason_t reason)
{
    switch (reason) {
    case ESP_RST_POWERON: return "power_on";
    case ESP_RST_EXT: return "external";
    case ESP_RST_SW: return "software";
    case ESP_RST_PANIC: return "panic";
    case ESP_RST_INT_WDT: return "interrupt_watchdog";
    case ESP_RST_TASK_WDT: return "task_watchdog";
    case ESP_RST_WDT: return "watchdog";
    case ESP_RST_DEEPSLEEP: return "deep_sleep";
    case ESP_RST_BROWNOUT: return "brownout";
    case ESP_RST_SDIO: return "sdio";
    default: return "unknown";
    }
}

static void record_http_result(int status, uint32_t started_ms)
{
    ++http_request_count;
    last_http_status = status;
    last_http_latency_ms = millis() - started_ms;
    if (status < 200 || status >= 400) {
        ++http_failure_count;
    }
}

static void finish_ota_attempt()
{
    if (ota_in_progress) {
        ota_total_ms = millis() - ota_started_ms;
        ota_in_progress = false;
    }
}

static void print_mlkem_public_key()
{
    Serial.println("ML-KEM public key:");
    for (size_t offset = 0; offset < sizeof(mlkem_public_key); offset += 16) {
        for (size_t index = offset; index < offset + 16 &&
             index < sizeof(mlkem_public_key); ++index) {
            Serial.printf("%02x", mlkem_public_key[index]);
        }
        Serial.println();
    }
}

static bool provision_mlkem_keypair()
{
    Preferences preferences;
    preferences.begin("mlkem", false);
    size_t public_length = preferences.getBytesLength("public");
    size_t secret_length = preferences.getBytesLength("secret");
    bool loaded = public_length == sizeof(mlkem_public_key) &&
                  secret_length == sizeof(mlkem_secret_key) &&
                  preferences.getBytes("public", mlkem_public_key,
                                       sizeof(mlkem_public_key)) == sizeof(mlkem_public_key) &&
                  preferences.getBytes("secret", mlkem_secret_key,
                                       sizeof(mlkem_secret_key)) == sizeof(mlkem_secret_key);

    if (!loaded) {
        disableCore0WDT();
        disableCore1WDT();
        /* ESP-IDF disables startup entropy before app code; re-enable it only
           around this first key generation, which runs before Wi-Fi starts. */
        bootloader_random_enable();
        int keypair_result = MLKEM768_keypair(mlkem_public_key, mlkem_secret_key);
        bootloader_random_disable();
        if (keypair_result != 0 ||
            preferences.putBytes("public", mlkem_public_key,
                                 sizeof(mlkem_public_key)) != sizeof(mlkem_public_key) ||
            preferences.putBytes("secret", mlkem_secret_key,
                                 sizeof(mlkem_secret_key)) != sizeof(mlkem_secret_key)) {
            preferences.end();
            return false;
        }
    }
    preferences.end();
    print_mlkem_public_key();
    return true;
}

static String server_url(const char *path)
{
    return String("http://") + SERVER_IP + ":" + SERVER_PORT + path;
}

static bool download_file(const char *path, unsigned char *buffer, size_t expected)
{
    HTTPClient http;
    WiFiClient client;
    String url = server_url(path);
    size_t received = 0;

    http.setTimeout(15000);
    uint32_t request_started_ms = millis();
    http.begin(client, url);
    int status = http.GET();
    record_http_result(status, request_started_ms);
    int content_length = http.getSize();
    if (status != HTTP_CODE_OK || content_length != static_cast<int>(expected)) {
        Serial.printf("Download %s failed: HTTP %d, content-length %d, expected %u\n",
                      path, status, content_length, static_cast<unsigned>(expected));
        http.end();
        return false;
    }

    WiFiClient *stream = http.getStreamPtr();
    while (received < expected) {
        size_t requested = expected - received;
        if (requested > 1024U) {
            requested = 1024U;
        }
        size_t count = stream->readBytes(reinterpret_cast<char *>(buffer + received), requested);
        if (count == 0) {
            Serial.printf("Download %s stopped at %u/%u bytes\n",
                          path, static_cast<unsigned>(received), static_cast<unsigned>(expected));
            http.end();
            return false;
        }
        received += count;
        if (ota_in_progress) ota_download_bytes += count;
    }
    http.end();
    Serial.printf("Downloaded %s: %u bytes\n", path, static_cast<unsigned>(received));
    return true;
}

static bool connect_wifi()
{
    if (WiFi.status() == WL_CONNECTED) {
        return true;
    }
    if (has_connected_once) ++wifi_reconnect_attempts;
    if (wifi_offline_since_ms == 0) wifi_offline_since_ms = millis();
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    for (unsigned int attempt = 0; attempt < 30 && WiFi.status() != WL_CONNECTED; attempt++) {
        delay(500);
        Serial.print('.');
    }
    Serial.println();
    bool connected = WiFi.status() == WL_CONNECTED;
    if (connected) {
        if (wifi_offline_since_ms != 0) {
            wifi_total_offline_ms += millis() - wifi_offline_since_ms;
            wifi_offline_since_ms = 0;
        }
        has_connected_once = true;
    }
    return connected;
}

static bool verify_digest(const unsigned char digest[SHA256_BLOCK_SIZE],
                            const unsigned char *signature,
                            const unsigned char *public_key,
                            int64_t *elapsed_us)
{
    unsigned long long recovered_length = 0;
    int64_t start_us;
    int result;

    memcpy(xmss_signed_message, signature, XMSS_SIG_BYTES);
    memcpy(xmss_signed_message + XMSS_SIG_BYTES, digest, SHA256_BLOCK_SIZE);
    start_us = esp_timer_get_time();
    result = xmss_sign_open(xmss_recovered_message, &recovered_length, xmss_signed_message,
                                XMSS_SIG_BYTES + SHA256_BLOCK_SIZE, public_key);
    *elapsed_us = esp_timer_get_time() - start_us;
    if (result == 0 && (recovered_length != SHA256_BLOCK_SIZE ||
                        memcmp(xmss_recovered_message, digest, SHA256_BLOCK_SIZE) != 0)) {
        result = -1;
    }
    return result == 0;
}

static bool hash_firmware(const char *path, size_t expected,
                          unsigned char digest[SHA256_BLOCK_SIZE])
{
    HTTPClient http;
    WiFiClient client;
    unsigned char buffer[4096];
    size_t received = 0;
    SHA256_CTX context;

    http.setTimeout(15000);
    uint32_t request_started_ms = millis();
    http.begin(client, server_url(path));
    int status = http.GET();
    record_http_result(status, request_started_ms);
    if (status != HTTP_CODE_OK || http.getSize() != static_cast<int>(expected)) {
        Serial.printf("Hash download %s failed: HTTP %d, content-length %d, expected %u\n",
                      path, status, http.getSize(), static_cast<unsigned>(expected));
        http.end();
        return false;
    }
    sha256_init(&context);
    WiFiClient *stream = http.getStreamPtr();
    unsigned long last_data_ms = millis();
    while (received < expected) {
        int available = stream->available();
        if (available <= 0) {
            if (millis() - last_data_ms > 20000UL) {
                Serial.printf("Hash download %s timed out at %u/%u bytes\n",
                              path, static_cast<unsigned>(received), static_cast<unsigned>(expected));
                http.end();
                return false;
            }
            delay(2);
            continue;
        }
        size_t requested = static_cast<size_t>(available);
        if (requested > sizeof(buffer)) requested = sizeof(buffer);
        int count = stream->read(reinterpret_cast<uint8_t *>(buffer), requested);
        if (count <= 0) {
            Serial.printf("Hash download %s read failed at %u/%u bytes\n",
                          path, static_cast<unsigned>(received), static_cast<unsigned>(expected));
            http.end();
            return false;
        }
        last_data_ms = millis();
        sha256_update(&context, buffer, static_cast<size_t>(count));
        received += static_cast<size_t>(count);
        if (ota_in_progress) ota_download_bytes += static_cast<size_t>(count);
    }
    sha256_final(&context, digest);
    http.end();
    return true;
}

static bool package_digest(unsigned int version, size_t plaintext_size,
                           size_t encrypted_size,
                           const unsigned char ciphertext_digest[SHA256_BLOCK_SIZE],
                           const unsigned char *kem_ciphertext,
                           const unsigned char nonce[AES_GCM_NONCE_BYTES],
                           const unsigned char tag[AES_GCM_TAG_BYTES],
                           unsigned char digest[SHA256_BLOCK_SIZE])
{
    unsigned char header[12];
    SHA256_CTX context;
    header[0] = static_cast<unsigned char>(version >> 24);
    header[1] = static_cast<unsigned char>(version >> 16);
    header[2] = static_cast<unsigned char>(version >> 8);
    header[3] = static_cast<unsigned char>(version);
    header[4] = static_cast<unsigned char>(plaintext_size >> 24);
    header[5] = static_cast<unsigned char>(plaintext_size >> 16);
    header[6] = static_cast<unsigned char>(plaintext_size >> 8);
    header[7] = static_cast<unsigned char>(plaintext_size);
    header[8] = static_cast<unsigned char>(encrypted_size >> 24);
    header[9] = static_cast<unsigned char>(encrypted_size >> 16);
    header[10] = static_cast<unsigned char>(encrypted_size >> 8);
    header[11] = static_cast<unsigned char>(encrypted_size);
    sha256_init(&context);
    sha256_update(&context, header, sizeof(header));
    sha256_update(&context, ciphertext_digest, SHA256_BLOCK_SIZE);
    sha256_update(&context, kem_ciphertext, MLKEM_CIPHERTEXT_BYTES);
    sha256_update(&context, nonce, AES_GCM_NONCE_BYTES);
    sha256_update(&context, tag, AES_GCM_TAG_BYTES);
    sha256_final(&context, digest);
    return true;
}

static bool install_encrypted_firmware(size_t encrypted_size, size_t plaintext_size,
                                       const unsigned char *kem_ciphertext,
                                       const unsigned char nonce[AES_GCM_NONCE_BYTES],
                                       const unsigned char tag[AES_GCM_TAG_BYTES])
{
    HTTPClient http;
    WiFiClient client;

    http.setTimeout(15000);
    unsigned char shared_secret[MLKEM_SSBYTES];
    if (MLKEM768_dec(shared_secret, kem_ciphertext, mlkem_secret_key) != 0) {
        Serial.println("ML-KEM decapsulation failed");
        return false;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int gcm_result = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                        shared_secret, 256);
    if (gcm_result == 0) {
        gcm_result = mbedtls_gcm_starts(&gcm, MBEDTLS_GCM_DECRYPT,
                                        nonce, AES_GCM_NONCE_BYTES, nullptr, 0);
    }
    if (gcm_result != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    http.begin(client, server_url("/firmware.bin"));
    uint32_t request_started_ms = millis();
    int status = http.GET();
    record_http_result(status, request_started_ms);
    int content_length = http.getSize();
    Serial.printf("OTA install start: HTTP %d, content-length %d, expected %u\n",
                  status, content_length, static_cast<unsigned>(encrypted_size));
    if (status != HTTP_CODE_OK || content_length != static_cast<int>(encrypted_size)) {
        mbedtls_gcm_free(&gcm);
        http.end();
        return false;
    }
    WiFiClient *stream = http.getStreamPtr();
    if (!Update.begin(plaintext_size, U_FLASH)) {
        Serial.printf("OTA begin failed: %s\n", Update.errorString());
        mbedtls_gcm_free(&gcm);
        http.end();
        return false;
    }
    unsigned char encrypted_buffer[4096];
    unsigned char plaintext_buffer[4096];
    size_t received = 0;
    size_t written = 0;
    while (received < encrypted_size) {
        size_t requested = encrypted_size - received;
        if (requested > sizeof(encrypted_buffer)) requested = sizeof(encrypted_buffer);
        size_t count = stream->readBytes(reinterpret_cast<char *>(encrypted_buffer), requested);
        if (count == 0 || mbedtls_gcm_update(&gcm, count, encrypted_buffer,
                                             plaintext_buffer) != 0 ||
            Update.write(plaintext_buffer, count) != count) {
            Update.abort();
            mbedtls_gcm_free(&gcm);
            http.end();
            return false;
        }
        received += count;
        written += count;
        yield();
    }
    unsigned char computed_tag[AES_GCM_TAG_BYTES];
    gcm_result = mbedtls_gcm_finish(&gcm, computed_tag, AES_GCM_TAG_BYTES);
    mbedtls_gcm_free(&gcm);
    Serial.printf("OTA decrypted stream wrote %u/%u bytes\n",
                  static_cast<unsigned>(written), static_cast<unsigned>(plaintext_size));
    http.end();
    if (gcm_result != 0 || written != plaintext_size ||
        memcmp(computed_tag, tag, AES_GCM_TAG_BYTES) != 0) {
        Update.abort();
        return false;
    }
    bool finished = Update.end(true);
    Serial.printf("OTA end: %s\n", finished ? "success" : Update.errorString());
    return finished;
}

static void report_status(const char *state, unsigned int version,
                          const char *reason = "",
                          int64_t verification_us = -1,
                          int firmware_size = -1)
{
    HTTPClient http;
    uint64_t offline_ms = wifi_total_offline_ms;
    if (wifi_offline_since_ms != 0) offline_ms += millis() - wifi_offline_since_ms;
    if (ota_in_progress) ota_total_ms = millis() - ota_started_ms;
    String body = String("{\"state\":\"") + state +
                  "\",\"device_id\":\"" + device_id +
                  "\",\"update_id\":\"" + current_update_id +
                  "\",\"version\":" + version +
                  ",\"build\":" + DIAGNOSTIC_BUILD +
                  ",\"chip_model\":\"" + ESP.getChipModel() +
                  "\",\"chip_revision\":" + ESP.getChipRevision() +
                  ",\"reset_reason\":\"" + boot_reset_reason + "\"" +
                  ",\"heap\":" + ESP.getFreeHeap() +
                  ",\"min_heap\":" + ESP.getMinFreeHeap() +
                  ",\"free_sketch_space\":" + ESP.getFreeSketchSpace() +
                  ",\"uptime_ms\":" + millis() +
                  ",\"rssi\":" + WiFi.RSSI() +
                  ",\"wifi_reconnect_attempts\":" + wifi_reconnect_attempts +
                  ",\"wifi_offline_ms\":" + static_cast<unsigned long long>(offline_ms) +
                  ",\"http_request_count\":" + http_request_count +
                  ",\"http_failure_count\":" + http_failure_count +
                  ",\"last_http_status\":" + last_http_status +
                  ",\"last_http_latency_ms\":" + last_http_latency_ms +
                  ",\"flash_bytes\":" + ESP.getFlashChipSize() +
                  ",\"firmware_size\":" + firmware_size +
                  ",\"verification_us\":" + verification_us +
                  ",\"ota_download_bytes\":" + static_cast<unsigned long long>(ota_download_bytes) +
                  ",\"ota_download_ms\":" + ota_download_ms +
                  ",\"ota_install_ms\":" + ota_install_ms +
                  ",\"ota_total_ms\":" + ota_total_ms +
                  ",\"reason\":\"" + reason + "\"";
#ifdef JOURNAL_DEVICE_STRESS
    body += journal_stress_status();
#endif
    body += "}";
    ++http_request_count;
    uint32_t request_started_ms = millis();
    http.begin(server_url("/status"));
    http.addHeader("Content-Type", "application/json");
    int status = http.POST(body);
    last_http_status = status;
    last_http_latency_ms = millis() - request_started_ms;
    if (status < 200 || status >= 400) ++http_failure_count;
    http.end();
    Serial.printf("Status: %s version %u\n", state, version);
}

static void check_for_update()
{
    HTTPClient http;
    int status;
    String manifest;
    unsigned int version = 0;
    int firmware_size = 0;
    int encrypted_size = 0;
    unsigned char *signature = nullptr;
    unsigned char *kem_ciphertext = nullptr;
    unsigned char nonce[AES_GCM_NONCE_BYTES];
    unsigned char tag[AES_GCM_TAG_BYTES];
    unsigned char public_key[XMSS_PK_BYTES];
    unsigned char ciphertext_digest[SHA256_BLOCK_SIZE];
    unsigned char digest[SHA256_BLOCK_SIZE];
    int64_t verification_us;
    uint32_t heap_before;
    uint32_t heap_after;

    uint32_t request_started_ms = millis();
    http.begin(server_url("/manifest.json"));
    status = http.GET();
    record_http_result(status, request_started_ms);
    if (status != HTTP_CODE_OK) {
        http.end();
        Serial.printf("Manifest request failed: %d\n", status);
        current_update_id[0] = '\0';
        report_status("failed", current_version, "manifest");
        return;
    }
    manifest = http.getString();
    http.end();
    sscanf(manifest.c_str(), "{\"version\":%u,\"size\":%d,\"encrypted_size\":%d}",
           &version, &firmware_size, &encrypted_size);
    if (version <= current_version || firmware_size <= 0 || encrypted_size <= 0 ||
        static_cast<size_t>(firmware_size) > MAX_FIRMWARE_BYTES ||
        static_cast<size_t>(encrypted_size) > MAX_FIRMWARE_BYTES) {
        current_update_id[0] = '\0';
        report_status("idle", current_version, "no_update", -1, firmware_size);
        return;
    }

    snprintf(current_update_id, sizeof(current_update_id), "%s-%u-%lu",
             device_id, version, static_cast<unsigned long>(millis()));
    ota_in_progress = true;
    ota_started_ms = millis();
    ota_download_ms = 0;
    ota_download_bytes = 0;
    ota_install_ms = 0;
    ota_total_ms = 0;
    report_status("downloading", version);
    signature = static_cast<unsigned char *>(malloc(XMSS_SIG_BYTES));
    if (signature == nullptr) {
        finish_ota_attempt();
        report_status("failed", version, "allocation", -1, firmware_size);
        current_update_id[0] = '\0';
        free(signature);
        return;
    }
    kem_ciphertext = static_cast<unsigned char *>(malloc(MLKEM_CIPHERTEXT_BYTES));
    if (kem_ciphertext == nullptr) {
        finish_ota_attempt();
        report_status("failed", version, "allocation", -1, firmware_size);
        current_update_id[0] = '\0';
        free(signature);
        return;
    }

    uint32_t download_started_ms = millis();
    bool package_downloaded =
        hash_firmware("/firmware.bin", static_cast<size_t>(encrypted_size), ciphertext_digest) &&
        download_file("/firmware.kem", kem_ciphertext, MLKEM_CIPHERTEXT_BYTES) &&
        download_file("/firmware.nonce", nonce, AES_GCM_NONCE_BYTES) &&
        download_file("/firmware.tag", tag, AES_GCM_TAG_BYTES) &&
        download_file("/firmware.sig", signature, XMSS_SIG_BYTES) &&
        download_file("/firmware.pub", public_key, XMSS_PK_BYTES);
    ota_download_ms = millis() - download_started_ms;
    if (!package_downloaded) {
        finish_ota_attempt();
        report_status("failed", version, "download", -1, firmware_size);
        current_update_id[0] = '\0';
        free(kem_ciphertext);
        free(signature);
        return;
    }
    if (memcmp(public_key, XMSS_TRUSTED_PUBLIC_KEY, sizeof(public_key)) != 0) {
        finish_ota_attempt();
        report_status("rejected", version, "publisher_key", -1, firmware_size);
        current_update_id[0] = '\0';
        free(kem_ciphertext);
        free(signature);
        return;
    }
    package_digest(version, static_cast<size_t>(firmware_size),
                   static_cast<size_t>(encrypted_size), ciphertext_digest,
                   kem_ciphertext, nonce, tag, digest);

    report_status("verifying", version, "", -1, firmware_size);
    heap_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    bool valid = verify_digest(digest, signature, public_key, &verification_us);
    heap_after = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    Serial.printf("Verification: %s, %lld us, heap %u -> %u\n", valid ? "ACCEPT" : "REJECT",
                  static_cast<long long>(verification_us), static_cast<unsigned>(heap_before), static_cast<unsigned>(heap_after));
    if (!valid) {
        finish_ota_attempt();
        report_status("rejected", version, "xmss", verification_us, firmware_size);
        current_update_id[0] = '\0';
        free(kem_ciphertext);
        free(signature);
        return;
    }

    report_status("installing", version, "", verification_us, firmware_size);
    uint32_t install_started_ms = millis();
    if (!install_encrypted_firmware(static_cast<size_t>(encrypted_size),
                                    static_cast<size_t>(firmware_size),
                                    kem_ciphertext, nonce, tag)) {
        ota_install_ms = millis() - install_started_ms;
        Serial.printf("OTA install failed: %s\n", Update.errorString());
        finish_ota_attempt();
        report_status("failed", version, "ota_install", verification_us, firmware_size);
        current_update_id[0] = '\0';
        free(kem_ciphertext);
        free(signature);
        return;
    }
    ota_install_ms = millis() - install_started_ms;
    finish_ota_attempt();
    report_status("installed", version, "", verification_us, firmware_size);
    current_update_id[0] = '\0';
    Preferences preferences;
    preferences.begin("xmss-ota", false);
    preferences.putUInt("version", version);
    preferences.end();
    free(kem_ciphertext);
    free(signature);
    delay(1000);
    ESP.restart();
}

void setup()
{
    Preferences preferences;
    Serial.begin(115200);
#ifdef JOURNAL_DEVICE_STRESS
    journal_stress_start();
#endif
    delay(1000);
    snprintf(device_id, sizeof(device_id), "%012llX",
             static_cast<unsigned long long>(ESP.getEfuseMac() & 0xFFFFFFFFFFFFULL));
    boot_reset_reason = reset_reason_name(esp_reset_reason());
    if (!provision_mlkem_keypair()) {
        Serial.println("ML-KEM key provisioning failed");
        return;
    }
    Serial.println("ML-KEM device key ready");
    preferences.begin("xmss-ota", true);
    current_version = preferences.getUInt("version", 1);
    preferences.end();
    Serial.printf("XMSS OTA diagnostic build %u: %s, current version %u\n",
                  DIAGNOSTIC_BUILD, XMSS_CFG_NAME, current_version);
    if (!connect_wifi()) {
        Serial.println("Wi-Fi connection failed");
        return;
    }
    Serial.print("ESP32 IP: ");
    Serial.println(WiFi.localIP());
    check_for_update();
    last_poll_ms = millis();
}

void loop()
{
#ifdef JOURNAL_DEVICE_STRESS
    journal_stress_poll();
#endif
    if (millis() - last_poll_ms >= POLL_INTERVAL_MS) {
        last_poll_ms = millis();
        if (connect_wifi()) check_for_update();
    }
    delay(50);
}
