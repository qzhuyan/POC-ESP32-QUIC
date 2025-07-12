/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include <stdio.h>
#include <inttypes.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_system.h"


#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "ngtcp2_sample.h"

#include "esp_log.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_task_wdt.h"

#include "protocol_examples_common.h"
#include "esp_wifi.h"
#include "nvs_flash.h"


#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"

#include "core_mqtt.h"
#include "core_mqtt_state.h"
#include "mqtt_quic_transport.h"

extern struct client g_client;

static const char *TAG = "quic_demo_main";

static uint8_t gbuffer[2048];  // Buffer for MQTT messages

// MQTT application callback
static void eventCallback(MQTTContext_t *pContext,
                         MQTTPacketInfo_t *pPacketInfo,
                         MQTTDeserializedInfo_t *pDeserializedInfo)
{
    ESP_LOGI(TAG, "MQTT Event: Packet Type=%d", pPacketInfo->type);
    
    switch (pPacketInfo->type) {
        case MQTT_PACKET_TYPE_CONNACK:
            ESP_LOGI(TAG, "=== MQTT CONNACK RECEIVED ===");
            if (pPacketInfo->remainingLength >= 2) {
                // CONNACK has 2 bytes: Connect Acknowledge Flags + Connect Return Code
                uint8_t flags = pPacketInfo->pRemainingData[0];
                uint8_t returnCode = pPacketInfo->pRemainingData[1];
                
                bool sessionPresent = (flags & 0x01) != 0;
                ESP_LOGI(TAG, "CONNACK - Session Present: %s", sessionPresent ? "true" : "false");
                ESP_LOGI(TAG, "CONNACK - Return Code: %d", returnCode);
                
                if (returnCode == 0) {
                    ESP_LOGI(TAG, "✓ MQTT Connection Successfully Established!");
                } else {
                    ESP_LOGE(TAG, "✗ MQTT Connection Failed with return code: %d", returnCode);
                }
            } else {
                ESP_LOGW(TAG, "CONNACK packet received but insufficient data");
            }
            break;
            
        case MQTT_PACKET_TYPE_PUBLISH:
            ESP_LOGI(TAG, "=== MQTT PUBLISH RECEIVED ===");
            if (pDeserializedInfo && pDeserializedInfo->pPublishInfo) {
                ESP_LOGI(TAG, "Topic: %.*s", 
                         pDeserializedInfo->pPublishInfo->topicNameLength,
                         pDeserializedInfo->pPublishInfo->pTopicName);
                ESP_LOGI(TAG, "Payload: %.*s", 
                         pDeserializedInfo->pPublishInfo->payloadLength,
                         (char *)pDeserializedInfo->pPublishInfo->pPayload);
                ESP_LOGI(TAG, "QoS: %d", pDeserializedInfo->pPublishInfo->qos);
            }
            break;
            
        case MQTT_PACKET_TYPE_PUBACK:
            ESP_LOGI(TAG, "=== MQTT PUBACK RECEIVED ===");
            if (pDeserializedInfo) {
                ESP_LOGI(TAG, "PUBACK - Packet ID: %d", pDeserializedInfo->packetIdentifier);
            }
            break;
            
        case MQTT_PACKET_TYPE_SUBACK:
            ESP_LOGI(TAG, "=== MQTT SUBACK RECEIVED ===");
            if (pDeserializedInfo) {
                ESP_LOGI(TAG, "SUBACK - Packet ID: %d", pDeserializedInfo->packetIdentifier);
            }
            // Parse SUBACK status codes from raw data if needed
            if (pPacketInfo->remainingLength >= 3) {
                ESP_LOGI(TAG, "SUBACK - Status codes available in raw data");
            }
            break;
            
        case MQTT_PACKET_TYPE_UNSUBACK:
            ESP_LOGI(TAG, "=== MQTT UNSUBACK RECEIVED ===");
            if (pDeserializedInfo) {
                ESP_LOGI(TAG, "UNSUBACK - Packet ID: %d", pDeserializedInfo->packetIdentifier);
            }
            break;
            
        case MQTT_PACKET_TYPE_PINGRESP:
            ESP_LOGI(TAG, "=== MQTT PINGRESP RECEIVED ===");
            break;
            
        default:
            ESP_LOGI(TAG, "=== UNKNOWN MQTT PACKET TYPE: %d ===", pPacketInfo->type);
            break;
    }
    
    // Log packet details for debugging
    ESP_LOGI(TAG, "Packet Details - Remaining Length: %zu, Type: 0x%02x", 
             pPacketInfo->remainingLength, pPacketInfo->type);
}

// Combined task that handles both QUIC and MQTT
void combined_quic_mqtt_task(void *pvParameters)
{
    ServerInfo_t *serverInfo = (ServerInfo_t *)pvParameters;
    if (!serverInfo) {
        ESP_LOGE(TAG, "No server info provided");
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Starting combined QUIC+MQTT task");
    ESP_LOGI(TAG, "Free heap at task start: %u bytes", esp_get_free_heap_size());
    
    // Convert port to string for QUIC config
    static char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", serverInfo->port);
    
    // Prepare QUIC client configuration
    quic_client_config_t quic_config = {
        .hostname = serverInfo->pHostName,
        .port = port_str,
        .alpn = serverInfo->pAlpn
    };

    ESP_LOGI(TAG, "Initializing QUIC client with %s:%s", quic_config.hostname, quic_config.port);
    ESP_LOGI(TAG, "Free heap before QUIC init: %u bytes", esp_get_free_heap_size());
    
    // Initialize QUIC client (non-blocking)
    if (quic_client_init_with_config(&quic_config) != 0) {
        ESP_LOGE(TAG, "Failed to initialize QUIC client");
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "QUIC client initialized, waiting for connection...");
    ESP_LOGI(TAG, "Free heap after QUIC init: %u bytes", esp_get_free_heap_size());
    
    // Wait for QUIC connection to be established
    int connection_attempts = 0;
    const int max_attempts = 200; // 20 seconds at 100ms intervals
    
    while (!quic_client_is_connected() && connection_attempts < max_attempts) {
        // Process QUIC events
        if (quic_client_process() != 0) {
            ESP_LOGE(TAG, "QUIC client process failed");
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
        connection_attempts++;
        
        // Reset watchdog periodically
        if (connection_attempts % 5 == 0) {
            // Just delay to prevent watchdog trigger
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        
        if (connection_attempts % 20 == 0) {
            ESP_LOGI(TAG, "Still waiting for QUIC connection... (%d/20s)", connection_attempts/20);
        }
    }

    if (!quic_client_is_connected()) {
        ESP_LOGE(TAG, "Failed to establish QUIC connection after %d attempts", max_attempts);
        quic_client_cleanup();
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "QUIC connection established! Waiting a bit more for stability...");

    // Wait a bit more to ensure connection is stable
    // why this is needed?
    vTaskDelay(pdMS_TO_TICKS(1000));
    connection_attempts = 0;
    while(!quic_client_local_stream_avail())
    {
        vTaskDelay(pdMS_TO_TICKS(100));
        ESP_LOGI(TAG, "Still waiting for QUIC streams... ");
    }
    
    // MQTT client setup
    MQTTContext_t mqttContext;
    MQTTStatus_t mqttStatus;
    NetworkContext_t networkContext;
    MQTTQUICConfig_t mqttQuicConfig = {
        .timeoutMs = 5000,
        .nonBlocking = false
    };
    
    // Initialize the transport layer
    BaseType_t transportStatus = mqtt_quic_transport_init(&networkContext, serverInfo, &mqttQuicConfig);
    if (transportStatus != pdPASS) {
        ESP_LOGE(TAG, "Failed to initialize transport");
        quic_client_cleanup();
        vTaskDelete(NULL);
        return;
    }
    
    // Set up the transport interface structure for core MQTT
    extern TransportInterface_t xTransportInterface;
    xTransportInterface.pNetworkContext = &networkContext;
    xTransportInterface.recv = mqtt_quic_transport_recv;
    xTransportInterface.send = mqtt_quic_transport_send;
    
    // Initialize MQTT library
    // @FIXME: this buffer isn't thread safe.
    MQTTFixedBuffer_t networkBuffer;
    networkBuffer.pBuffer = gbuffer;
    networkBuffer.size = sizeof(gbuffer);
    
    ESP_LOGD(TAG, "Free heap before MQTT init: %u bytes", esp_get_free_heap_size());
    
    extern uint32_t mqtt_get_time_ms(void);
    mqttStatus = MQTT_Init(&mqttContext,
                          &xTransportInterface,
                          mqtt_get_time_ms,
                          eventCallback,
                          &networkBuffer);
                          
    if (mqttStatus != MQTTSuccess) {
        ESP_LOGE(TAG, "Failed to initialize MQTT, error %d", mqttStatus);
        quic_client_cleanup();
        vTaskDelete(NULL);
        return;
    }
    
    ESP_LOGI(TAG, "MQTT initialized, connecting to broker...");

    // Connect to the MQTT broker
    MQTTConnectInfo_t connectInfo;
    memset(&connectInfo, 0, sizeof(connectInfo));
    connectInfo.cleanSession = true;
    connectInfo.pClientIdentifier = "esp32_quic_client";
    connectInfo.clientIdentifierLength = strlen("esp32_quic_client");
    
    // Add more debugging before MQTT connect
    ESP_LOGI(TAG, "About to call MQTT_Connect with:");
    ESP_LOGI(TAG, "  Client ID: %s", connectInfo.pClientIdentifier);
    ESP_LOGI(TAG, "  Clean session: %s", connectInfo.cleanSession ? "true" : "false");
    ESP_LOGI(TAG, "  QUIC connected: %s", quic_client_is_connected() ? "true" : "false");
    ESP_LOGI(TAG, "  Free heap: %u bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "Calling MQTT_Connect with tieout...");
    
    bool sessionPresent = false;
    
    // Use a shorter timeout for MQTT connect to prevent watchdog
    mqttStatus = MQTT_Connect(&mqttContext, &connectInfo, NULL, 5000, &sessionPresent);
    
    ESP_LOGI(TAG, "MQTT_Connect returned: %d, sessionPresent: %s", mqttStatus, sessionPresent ? "true" : "false");
    if (mqttStatus != MQTTSuccess) {
        ESP_LOGE(TAG, "Failed to connect to MQTT broker, error %d", mqttStatus);
        quic_client_cleanup();
        vTaskDelete(NULL);
        return;
    }
    
    ESP_LOGI(TAG, "Connected to MQTT broker over QUIC!");
    
    // Give some time for CONNACK to be processed
    ESP_LOGI(TAG, "Waiting for CONNACK processing...");
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    // Subscribe to a topic
    MQTTSubscribeInfo_t subscribeInfo;
    subscribeInfo.qos = MQTTQoS0;
    subscribeInfo.pTopicFilter = "esp32/quic/test";
    subscribeInfo.topicFilterLength = strlen("esp32/quic/test");
    
    mqttStatus = MQTT_Subscribe(&mqttContext, &subscribeInfo, 1, 2);
    if (mqttStatus != MQTTSuccess) {
        ESP_LOGE(TAG, "Failed to subscribe to topic, error %d", mqttStatus);
    } else {
        ESP_LOGI(TAG, "Subscribed to topic esp32/quic/test");
    }
    
    // Publish a message
    MQTTPublishInfo_t publishInfo;
    memset(&publishInfo, 0, sizeof(publishInfo));
    publishInfo.qos = MQTTQoS0;
    publishInfo.pTopicName = "esp32/quic/test";
    publishInfo.topicNameLength = strlen("esp32/quic/test");
    publishInfo.pPayload = "Hello from ESP32 over MQTT+QUIC!";
    publishInfo.payloadLength = strlen("Hello from ESP32 over MQTT+QUIC!");
    
    mqttStatus = MQTT_Publish(&mqttContext, &publishInfo, 3);
    if (mqttStatus != MQTTSuccess) {
        ESP_LOGE(TAG, "Failed to publish message, error %d", mqttStatus);
    } else {
        ESP_LOGI(TAG, "Published message to esp32/quic/test");
    }
    
    // Main loop - process both QUIC and MQTT
    ESP_LOGI(TAG, "Entering main processing loop...");
    int loop_count = 0;
    while (1) {
        // Prevent watchdog trigger with regular delays
        vTaskDelay(pdMS_TO_TICKS(20));  // Increased delay to reduce processing frequency
        loop_count++;
        
        // Process QUIC events less frequently to avoid overwhelming ngtcp2
        if (loop_count % 25 == 0) {  // Process QUIC every 25 iterations (every 500ms)
            if (quic_client_process() != 0) {
                ESP_LOGW(TAG, "QUIC client process failed");
                // Don't break immediately on failure, give it another chance
                vTaskDelay(pdMS_TO_TICKS(100));
            }
        }
        
        // Process MQTT events more frequently to catch all incoming messages
        if (loop_count % 5 == 0) {  // Process MQTT every 5 iterations (every 100ms)
            mqttStatus = MQTT_ProcessLoop(&mqttContext);
            if (mqttStatus != MQTTSuccess) {
                ESP_LOGW(TAG, "MQTT process loop failed, error %d", mqttStatus);
            }
        }
        
        // Check if QUIC connection is still alive
        if (!quic_client_is_connected()) {
            ESP_LOGW(TAG, "QUIC connection lost");
            break;
        }
        
        // Check free heap every 50 iterations
        if (loop_count % 50 == 0) {
            ESP_LOGD(TAG, "Free heap: %u bytes (loop %d)", esp_get_free_heap_size(), loop_count);
        }
    }
    
    ESP_LOGI(TAG, "Cleaning up and exiting...");
    quic_client_cleanup();
    vTaskDelete(NULL);
}

void wifi_init(void)
{
    printf("init wifi...\n");
    // System initialization
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(example_connect());

    wifi_ap_record_t ap_info;
    ESP_ERROR_CHECK(esp_wifi_sta_get_ap_info(&ap_info));
    ESP_LOGI(TAG, "--- Access Point Information ---");
    ESP_LOG_BUFFER_HEX("MAC Address", ap_info.bssid, sizeof(ap_info.bssid));
    ESP_LOG_BUFFER_CHAR("SSID", ap_info.ssid, sizeof(ap_info.ssid));
    ESP_LOGI(TAG, "Primary Channel: %d", ap_info.primary);
    ESP_LOGI(TAG, "RSSI: %d", ap_info.rssi);
    printf("init wifi done!\n");

}
void app_main(void)
{
    ESP_LOGI(TAG, "Initializing...");
    
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // Connect to WiFi
    ESP_LOGI(TAG, "Connecting to WiFi...");
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect());
    
    ESP_LOGI(TAG, "WiFi connected, starting combined QUIC+MQTT task...");
    
    // Log memory status before starting
    ESP_LOGI(TAG, "Free heap before task creation: %u bytes", esp_get_free_heap_size());
    
    // Create server info for QUIC client
    static ServerInfo_t serverInfo = {
        .pHostName = "broker.emqx.io",
        .port = 14567,
        .pAlpn = "mqtt"  // Use plain string instead of binary format
    };
    
    // Run the combined QUIC+MQTT task with smaller stack
    xTaskCreate(combined_quic_mqtt_task, "quic_mqtt_task", 28*1024, &serverInfo, 5, NULL);

    while (1) {
         vTaskDelay(10000 / portTICK_PERIOD_MS); // Yield to other tasks
    }
}
