#pragma once

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>

static QueueHandle_t journal_stress_queue = nullptr;
static volatile uint32_t journal_stress_mode = 0;
static volatile uint32_t journal_stress_bytes = 0;
static volatile uint32_t journal_stress_deadline = 0;
static volatile uint32_t journal_stress_busy_us = 0;
static volatile uint32_t journal_stress_ticks = 0;

static String journal_stress_status()
{
    uint32_t deadline = journal_stress_deadline;
    int32_t remaining = static_cast<int32_t>(deadline - millis());
    return String(",\"stress_build\":1,\"stress_mode\":") + journal_stress_mode +
           ",\"stress_bytes\":" + journal_stress_bytes +
           ",\"stress_remaining_ms\":" + (remaining > 0 ? remaining : 0) +
           ",\"stress_busy_us\":" + journal_stress_busy_us +
           ",\"stress_task_ticks\":" + journal_stress_ticks;
}

static void journal_stress_task(void *)
{
    void *blocks[40] = {};
    size_t count = 0;
    for (;;) {
        uint8_t command = 0;
        bool received = xQueueReceive(journal_stress_queue, &command, 0) == pdTRUE;
        bool expired = journal_stress_mode != 0 &&
                       static_cast<int32_t>(millis() - journal_stress_deadline) >= 0;
        if (received || expired) {
            journal_stress_mode = 0;
            journal_stress_deadline = 0;
            while (count) free(blocks[--count]);
            journal_stress_bytes = 0;
            if (received && command != 0) {
                if (command == 1) {
                    while (count < 40 && ESP.getFreeHeap() > 95000) {
                        void *block = heap_caps_malloc(4096, MALLOC_CAP_8BIT);
                        if (!block) break;
                        memset(block, 0x5a, 4096);
                        blocks[count++] = block;
                    }
                    journal_stress_bytes = count * 4096;
                }
                journal_stress_deadline = millis() + 90000;
                journal_stress_mode = command;
            }
            Serial.println(String("JSTRESS {") + journal_stress_status().substring(1) + "}");
        }
        if (journal_stress_mode == 2) {
            int64_t started = esp_timer_get_time();
            volatile uint32_t accumulator = 1;
            while (esp_timer_get_time() - started < 30000) {
                accumulator = accumulator * 1664525U + 1013904223U;
            }
            journal_stress_busy_us += static_cast<uint32_t>(esp_timer_get_time() - started);
        }
        ++journal_stress_ticks;
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

static void journal_stress_start()
{
    journal_stress_queue = xQueueCreate(4, sizeof(uint8_t));
    if (!journal_stress_queue ||
        xTaskCreatePinnedToCore(journal_stress_task, "journal-stress", 3072, nullptr,
                                1, nullptr, 1) != pdPASS) {
        Serial.println("JSTRESS initialization failed");
    }
}

static void journal_stress_poll()
{
    static char input[32];
    static size_t used = 0;
    while (Serial.available()) {
        char value = static_cast<char>(Serial.read());
        if (value == '\r') continue;
        if (value == '\n') {
            input[used] = '\0';
            uint8_t command = 0;
            bool known = true;
            if (strcmp(input, "JSTRESS RAM") == 0) command = 1;
            else if (strcmp(input, "JSTRESS CPU") == 0) command = 2;
            else if (strcmp(input, "JSTRESS STOP") != 0) known = false;
            if (known && journal_stress_queue) xQueueSend(journal_stress_queue, &command, 0);
            used = 0;
        } else if (used + 1 < sizeof(input)) {
            input[used++] = value;
        } else {
            used = 0;
        }
    }
}
