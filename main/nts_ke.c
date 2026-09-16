#include "nts_ke.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "app_config.h"
#include "app_state.h"
#include "key_store.h"
#include "nts_aes_siv.h"
#include "nts_cookie.h"

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "psa/crypto.h"

#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

static const char *TAG = "NTS_KE";

/*
 * NTS-KE record types.
 */
#define NTS_KE_RECORD_END_OF_MESSAGE       0x0000U
#define NTS_KE_RECORD_NEXT_PROTOCOL         0x0001U
#define NTS_KE_RECORD_AEAD_ALGORITHM        0x0004U
#define NTS_KE_RECORD_NEW_COOKIE            0x0005U

#define NTS_KE_CRITICAL_BIT                 0x8000U

/*
 * NTS protocol and AEAD identifiers.
 */
#define NTS_KE_PROTOCOL_NTPV4               0x0000U
#define NTS_KE_AEAD_AES_SIV_CMAC_256        0x000FU

#define NTS_KE_MAX_RECORD_LENGTH            1024U
#define NTS_KE_CERT_MAX_LENGTH              8192U
#define NTS_KE_KEY_MAX_LENGTH               8192U

#define NTS_KE_TASK_STACK_SIZE              12288U
#define NTS_KE_TASK_PRIORITY                9U

static const char NTS_EXPORTER_LABEL[] =
    "EXPORTER-network-time-security";

static const unsigned char NTS_C2S_CONTEXT[5] = {
    0x00, 0x00,     /* NTPv4 protocol ID */
    0x00, 0x0F,     /* AEAD AES-SIV-CMAC-256 */
    0x00            /* Client-to-server */
};

static const unsigned char NTS_S2C_CONTEXT[5] = {
    0x00, 0x00,     /* NTPv4 protocol ID */
    0x00, 0x0F,     /* AEAD AES-SIV-CMAC-256 */
    0x01            /* Server-to-client */
};

static const char *NTS_ALPN_PROTOCOLS[] = {
    "ntske/1",
    NULL
};

typedef struct {
    int socket_fd;
} nts_ke_bio_context_t;

typedef struct {
    mbedtls_x509_crt certificate_chain;
    mbedtls_pk_context private_key;
    mbedtls_ssl_config ssl_config;

    uint8_t *certificate_pem;
    size_t certificate_pem_len;

    uint8_t *private_key_pem;
    size_t private_key_pem_len;

    bool initialized;
} nts_ke_server_context_t;

static nts_ke_server_context_t s_server_context;
static TaskHandle_t s_nts_ke_task;

static uint16_t read_u16_be(
    const uint8_t *source)
{
    return (uint16_t)(
        ((uint16_t)source[0] << 8) |
        source[1]);
}

static void write_u16_be(
    uint8_t *destination,
    uint16_t value)
{
    destination[0] = (uint8_t)(value >> 8);
    destination[1] = (uint8_t)value;
}

static uint64_t nts_ke_current_ntp_seconds(void)
{
    ntp_timestamp_t timestamp;

    app_state_get_ntp_timestamp(&timestamp);

    return timestamp.seconds;
}

static void nts_ke_zero_free(
    uint8_t *buffer,
    size_t length)
{
    if (buffer != NULL) {
        key_store_zeroize(buffer, length);
        free(buffer);
    }
}

static int nts_ke_bio_send(
    void *context,
    const unsigned char *buffer,
    size_t length)
{
    nts_ke_bio_context_t *bio =
        (nts_ke_bio_context_t *)context;

    if (bio == NULL ||
        bio->socket_fd < 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    int result = send(
        bio->socket_fd,
        buffer,
        length,
        0);

    if (result >= 0) {
        return result;
    }

    if (errno == EAGAIN ||
        errno == EWOULDBLOCK) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int nts_ke_bio_recv(
    void *context,
    unsigned char *buffer,
    size_t length)
{
    nts_ke_bio_context_t *bio =
        (nts_ke_bio_context_t *)context;

    if (bio == NULL ||
        bio->socket_fd < 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    int result = recv(
        bio->socket_fd,
        buffer,
        length,
        0);

    if (result > 0) {
        return result;
    }

    if (result == 0) {
        return MBEDTLS_ERR_SSL_CONN_EOF;
    }

    if (errno == EAGAIN ||
        errno == EWOULDBLOCK) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int nts_ke_ssl_read_exact(
    mbedtls_ssl_context *ssl,
    uint8_t *buffer,
    size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        int result = mbedtls_ssl_read(
            ssl,
            &buffer[offset],
            length - offset);

        if (result == MBEDTLS_ERR_SSL_WANT_READ ||
            result == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (result <= 0) {
            return result;
        }

        offset += (size_t)result;
    }

    return 0;
}

static int nts_ke_ssl_write_all(
    mbedtls_ssl_context *ssl,
    const uint8_t *buffer,
    size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        int result = mbedtls_ssl_write(
            ssl,
            &buffer[offset],
            length - offset);

        if (result == MBEDTLS_ERR_SSL_WANT_READ ||
            result == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (result <= 0) {
            return result;
        }

        offset += (size_t)result;
    }

    return 0;
}

static int nts_ke_read_record(
    mbedtls_ssl_context *ssl,
    uint16_t *record_type,
    uint8_t *payload,
    size_t payload_capacity,
    size_t *payload_length)
{
    uint8_t header[4];

    int result = nts_ke_ssl_read_exact(
        ssl,
        header,
        sizeof(header));

    if (result != 0) {
        return result;
    }

    *record_type = read_u16_be(&header[0]);

    uint16_t record_length =
        read_u16_be(&header[2]);

    if (record_length > payload_capacity) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (record_length > 0U) {
        result = nts_ke_ssl_read_exact(
            ssl,
            payload,
            record_length);

        if (result != 0) {
            return result;
        }
    }

    *payload_length = record_length;

    return 0;
}

static int nts_ke_write_record(
    mbedtls_ssl_context *ssl,
    uint16_t record_type,
    const uint8_t *payload,
    size_t payload_length)
{
    if (payload_length > UINT16_MAX) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    uint8_t header[4];

    write_u16_be(&header[0], record_type);
    write_u16_be(&header[2],
                 (uint16_t)payload_length);

    int result = nts_ke_ssl_write_all(
        ssl,
        header,
        sizeof(header));

    if (result != 0) {
        return result;
    }

    if (payload_length > 0U) {
        result = nts_ke_ssl_write_all(
            ssl,
            payload,
            payload_length);
    }

    return result;
}

static esp_err_t nts_ke_load_blob(
    esp_err_t (*loader)(uint8_t *, size_t *),
    uint8_t **buffer,
    size_t *buffer_length,
    size_t maximum_length)
{
    if (loader == NULL ||
        buffer == NULL ||
        buffer_length == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *buffer = NULL;
    *buffer_length = 0U;

    size_t required_length = 0U;

    esp_err_t err = loader(
        NULL,
        &required_length);

    if (err != ESP_OK) {
        return err;
    }

    if (required_length == 0U ||
        required_length >= maximum_length) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t *allocated =
        calloc(1U, required_length + 1U);

    if (allocated == NULL) {
        return ESP_ERR_NO_MEM;
    }

    size_t loaded_length =
        required_length;

    err = loader(
        allocated,
        &loaded_length);

    if (err != ESP_OK) {
        nts_ke_zero_free(
            allocated,
            required_length + 1U);

        return err;
    }

    allocated[loaded_length] = '\0';

    *buffer = allocated;
    *buffer_length = loaded_length;

    return ESP_OK;
}

static esp_err_t nts_ke_export_traffic_keys(
    mbedtls_ssl_context *ssl,
    nts_cookie_keys_t *keys)
{
    if (ssl == NULL ||
        keys == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    int result =
        mbedtls_ssl_export_keying_material(
            ssl,
            keys->c2s_key,
            NTS_TRAFFIC_KEY_LEN,
            NTS_EXPORTER_LABEL,
            sizeof(NTS_EXPORTER_LABEL) - 1U,
            NTS_C2S_CONTEXT,
            sizeof(NTS_C2S_CONTEXT),
            1);

    if (result != 0) {
        key_store_zeroize(
            keys->c2s_key,
            sizeof(keys->c2s_key));

        key_store_zeroize(
            keys->s2c_key,
            sizeof(keys->s2c_key));

        return ESP_FAIL;
    }

    result =
        mbedtls_ssl_export_keying_material(
            ssl,
            keys->s2c_key,
            NTS_TRAFFIC_KEY_LEN,
            NTS_EXPORTER_LABEL,
            sizeof(NTS_EXPORTER_LABEL) - 1U,
            NTS_S2C_CONTEXT,
            sizeof(NTS_S2C_CONTEXT),
            1);

    if (result != 0) {
        key_store_zeroize(
            keys->c2s_key,
            sizeof(keys->c2s_key));

        key_store_zeroize(
            keys->s2c_key,
            sizeof(keys->s2c_key));

        return ESP_FAIL;
    }

    return ESP_OK;
}

static int nts_ke_parse_client_records(
    mbedtls_ssl_context *ssl)
{
    bool protocol_supported = false;
    bool aead_supported = false;
    bool end_received = false;

    uint8_t next_protocol_records = 0U;
    uint8_t aead_records = 0U;

    uint8_t payload[NTS_KE_MAX_RECORD_LENGTH];

    while (!end_received) {
        uint16_t record_type = 0U;
        size_t payload_length = 0U;

        int result = nts_ke_read_record(
            ssl,
            &record_type,
            payload,
            sizeof(payload),
            &payload_length);

        if (result != 0) {
            return result;
        }

        bool critical =
            (record_type & NTS_KE_CRITICAL_BIT) != 0U;

        uint16_t type =
            record_type & ~NTS_KE_CRITICAL_BIT;

        switch (type) {
        case NTS_KE_RECORD_END_OF_MESSAGE:
            if (!critical ||
                payload_length != 0U) {
                return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            }

            end_received = true;
            break;

        case NTS_KE_RECORD_NEXT_PROTOCOL:
            next_protocol_records++;

            if (next_protocol_records != 1U ||
                !critical ||
                payload_length == 0U ||
                (payload_length & 0x01U) != 0U) {
                return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            }

            for (size_t i = 0U;
                 i < payload_length;
                 i += 2U) {
                uint16_t protocol =
                    read_u16_be(&payload[i]);

                if (protocol ==
                    NTS_KE_PROTOCOL_NTPV4) {
                    protocol_supported = true;
                }
            }
            break;

        case NTS_KE_RECORD_AEAD_ALGORITHM:
            aead_records++;

            if (aead_records != 1U ||
                !critical ||
                payload_length == 0U ||
                (payload_length & 0x01U) != 0U) {
                return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            }

            for (size_t i = 0U;
                 i < payload_length;
                 i += 2U) {
                uint16_t algorithm =
                    read_u16_be(&payload[i]);

                if (algorithm ==
                    NTS_KE_AEAD_AES_SIV_CMAC_256) {
                    aead_supported = true;
                }
            }
            break;

        default:
            if (critical) {
                return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            }
            break;
        }
    }

    if (!protocol_supported ||
        !aead_supported ||
        next_protocol_records != 1U ||
        aead_records != 1U) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    return 0;
}

static int nts_ke_write_server_records(
    mbedtls_ssl_context *ssl,
    nts_cookie_keys_t *keys)
{
    uint8_t selected_protocol[2];
    uint8_t selected_aead[2];

    write_u16_be(
        selected_protocol,
        NTS_KE_PROTOCOL_NTPV4);

    write_u16_be(
        selected_aead,
        NTS_KE_AEAD_AES_SIV_CMAC_256);

    int result = nts_ke_write_record(
        ssl,
        NTS_KE_CRITICAL_BIT |
            NTS_KE_RECORD_NEXT_PROTOCOL,
        selected_protocol,
        sizeof(selected_protocol));

    if (result != 0) {
        return result;
    }

    result = nts_ke_write_record(
        ssl,
        NTS_KE_CRITICAL_BIT |
            NTS_KE_RECORD_AEAD_ALGORITHM,
        selected_aead,
        sizeof(selected_aead));

    if (result != 0) {
        return result;
    }

    for (uint32_t i = 0U;
         i < APP_NTS_MAX_COOKIE_COUNT;
         i++) {
        uint8_t cookie[NTS_COOKIE_MAX_LEN];

        size_t cookie_length =
            sizeof(cookie);

        uint64_t now_ntp =
            nts_ke_current_ntp_seconds();

        keys->issued_ntp_seconds =
            now_ntp;

        keys->expires_ntp_seconds =
            now_ntp +
            APP_NTS_COOKIE_LIFETIME_SECONDS;

        esp_err_t err = nts_cookie_create(
            keys,
            cookie,
            &cookie_length);

        if (err != ESP_OK) {
            key_store_zeroize(
                cookie,
                sizeof(cookie));

            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }

        result = nts_ke_write_record(
            ssl,
            NTS_KE_RECORD_NEW_COOKIE,
            cookie,
            cookie_length);

        key_store_zeroize(
            cookie,
            sizeof(cookie));

        if (result != 0) {
            return result;
        }
    }

    return nts_ke_write_record(
        ssl,
        NTS_KE_CRITICAL_BIT |
            NTS_KE_RECORD_END_OF_MESSAGE,
        NULL,
        0U);
}

static void nts_ke_handle_client(
    int client_socket)
{
    nts_ke_bio_context_t bio = {
        .socket_fd = client_socket,
    };

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);

    int result = mbedtls_ssl_setup(
        &ssl,
        &s_server_context.ssl_config);

    if (result != 0) {
        mbedtls_ssl_free(&ssl);
        close(client_socket);
        return;
    }

    mbedtls_ssl_set_bio(
        &ssl,
        &bio,
        nts_ke_bio_send,
        nts_ke_bio_recv,
        NULL);

    while (true) {
        result = mbedtls_ssl_handshake(&ssl);

        if (result == 0) {
            break;
        }

        if (result == MBEDTLS_ERR_SSL_WANT_READ ||
            result == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        ESP_LOGW(TAG,
                 "TLS handshake failed: %d",
                 result);

        mbedtls_ssl_free(&ssl);
        close(client_socket);
        return;
    }

    const char *tls_version =
        mbedtls_ssl_get_version(&ssl);

    if (tls_version == NULL ||
        strcmp(tls_version, "TLSv1.3") != 0) {
        ESP_LOGW(TAG,
                 "NTS-KE rejected non-TLS-1.3 client");

        (void)mbedtls_ssl_close_notify(&ssl);
        mbedtls_ssl_free(&ssl);
        close(client_socket);
        return;
    }

    const char *alpn =
        mbedtls_ssl_get_alpn_protocol(&ssl);

    if (alpn == NULL ||
        strcmp(alpn, "ntske/1") != 0) {
        ESP_LOGW(TAG,
                 "NTS-KE ALPN negotiation failed");

        (void)mbedtls_ssl_close_notify(&ssl);
        mbedtls_ssl_free(&ssl);
        close(client_socket);
        return;
    }

    result = nts_ke_parse_client_records(&ssl);

    if (result != 0) {
        ESP_LOGW(TAG,
                 "Invalid NTS-KE record sequence");

        (void)mbedtls_ssl_close_notify(&ssl);
        mbedtls_ssl_free(&ssl);
        close(client_socket);
        return;
    }

    nts_cookie_keys_t traffic_keys;
    memset(&traffic_keys, 0, sizeof(traffic_keys));

    esp_err_t err = nts_ke_export_traffic_keys(
        &ssl,
        &traffic_keys);

    if (err != ESP_OK) {
        ESP_LOGW(TAG,
                 "NTS exporter failed");

        key_store_zeroize(
            &traffic_keys,
            sizeof(traffic_keys));

        (void)mbedtls_ssl_close_notify(&ssl);
        mbedtls_ssl_free(&ssl);
        close(client_socket);
        return;
    }

    result = nts_ke_write_server_records(
        &ssl,
        &traffic_keys);

    key_store_zeroize(
        &traffic_keys,
        sizeof(traffic_keys));

    if (result != 0) {
        ESP_LOGW(TAG,
                 "NTS-KE response write failed: %d",
                 result);
    }

    (void)mbedtls_ssl_close_notify(&ssl);

    mbedtls_ssl_free(&ssl);

    close(client_socket);
}

static void nts_ke_server_task(void *arg)
{
    (void)arg;

    int listen_socket = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_IP);

    if (listen_socket < 0) {
        ESP_LOGE(TAG,
                 "NTS-KE socket creation failed");

        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in server_address = {
        .sin_family = AF_INET,
        .sin_port = htons(APP_NTS_KE_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    if (bind(listen_socket,
             (struct sockaddr *)&server_address,
             sizeof(server_address)) != 0) {
        ESP_LOGE(TAG,
                 "NTS-KE bind failed: errno=%d",
                 errno);

        close(listen_socket);
        vTaskDelete(NULL);
        return;
    }

    if (listen(listen_socket, 2) != 0) {
        ESP_LOGE(TAG,
                 "NTS-KE listen failed: errno=%d",
                 errno);

        close(listen_socket);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG,
             "NTS-KE listening on TCP %u",
             APP_NTS_KE_PORT);

    while (true) {
        struct sockaddr_in client_address = {0};

        socklen_t client_length =
            sizeof(client_address);

        int client_socket = accept(
            listen_socket,
            (struct sockaddr *)&client_address,
            &client_length);

        if (client_socket < 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        nts_ke_handle_client(client_socket);
    }
}

esp_err_t nts_ke_start(void)
{
    if (s_server_context.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = key_store_init();

    if (err != ESP_OK) {
        return err;
    }

    err = key_store_ensure_cookie_keyring();

    if (err != ESP_OK) {
        return err;
    }

    err = nts_aes_siv_init();

    if (err != ESP_OK) {
        return err;
    }

    psa_status_t psa_result = psa_crypto_init();

    if (psa_result != PSA_SUCCESS) {
        return ESP_FAIL;
    }

    /* Remaining nts_ke_start() code continues here. */

    memset(&s_server_context,
           0,
           sizeof(s_server_context));

    mbedtls_x509_crt_init(
        &s_server_context.certificate_chain);

    mbedtls_pk_init(
        &s_server_context.private_key);

    mbedtls_ssl_config_init(
        &s_server_context.ssl_config);

 /*   err = nts_ke_load_blob(
  *      key_store_load_tls_certificate,
  *      &s_server_context.certificate_pem,
  *      &s_server_context.certificate_pem_len,
  *      NTS_KE_CERT_MAX_LENGTH);
  *
  * if (err != ESP_OK) {
  *      return err;
  *  }
  */
	err = nts_ke_load_blob(
		key_store_load_tls_private_key,
		&s_server_context.private_key_pem,
		&s_server_context.private_key_pem_len,
		NTS_KE_KEY_MAX_LENGTH);

	if (err != ESP_OK) {
		ESP_LOGE(TAG,
				 "Missing NVS blob: tls_server_key (%s)",
				 esp_err_to_name(err));

		return err;
	}
 /*   err = nts_ke_load_blob(
  *      key_store_load_tls_private_key,
  *      &s_server_context.private_key_pem,
  *      &s_server_context.private_key_pem_len,
  *      NTS_KE_KEY_MAX_LENGTH);
  *
  *  if (err != ESP_OK) {
  *      nts_ke_zero_free(
  *          s_server_context.certificate_pem,
  *          s_server_context.certificate_pem_len + 1U);
  *
  *      return err;
  *  }
  */
    int result = mbedtls_x509_crt_parse(
        &s_server_context.certificate_chain,
        s_server_context.certificate_pem,
        s_server_context.certificate_pem_len + 1U);

    if (result != 0) {
        return ESP_FAIL;
    }

    result = mbedtls_pk_parse_key(
        &s_server_context.private_key,
        s_server_context.private_key_pem,
        s_server_context.private_key_pem_len + 1U,
        NULL,
        0U);

    if (result != 0) {
        return ESP_FAIL;
    }

    result = mbedtls_ssl_config_defaults(
        &s_server_context.ssl_config,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);

    if (result != 0) {
        return ESP_FAIL;
    }

    mbedtls_ssl_conf_authmode(
        &s_server_context.ssl_config,
        MBEDTLS_SSL_VERIFY_NONE);

    result = mbedtls_ssl_conf_alpn_protocols(
        &s_server_context.ssl_config,
        NTS_ALPN_PROTOCOLS);

    if (result != 0) {
        return ESP_FAIL;
    }

    result = mbedtls_ssl_conf_own_cert(
        &s_server_context.ssl_config,
        &s_server_context.certificate_chain,
        &s_server_context.private_key);

    if (result != 0) {
        return ESP_FAIL;
    }

    s_server_context.initialized = true;

    BaseType_t task_result = xTaskCreate(
        nts_ke_server_task,
        "nts_ke",
        NTS_KE_TASK_STACK_SIZE,
        NULL,
        NTS_KE_TASK_PRIORITY,
        &s_nts_ke_task);

    if (task_result != pdPASS) {
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}