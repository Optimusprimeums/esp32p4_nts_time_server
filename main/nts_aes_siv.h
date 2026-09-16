#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/*
 * AEAD_AES_SIV_CMAC_256
 *
 * Total key size: 32 bytes
 *   Bytes  0-15: AES-CMAC / S2V key
 *   Bytes 16-31: AES-CTR key
 *
 * Output format:
 *   16-byte synthetic IV/authentication tag
 *   followed by ciphertext bytes.
 */
#define NTS_AES_SIV_KEY_LEN       32U
#define NTS_AES_SIV_TAG_LEN       16U
#define NTS_AES_SIV_NONCE_LEN     16U

esp_err_t nts_aes_siv_init(void);

esp_err_t nts_aes_siv_encrypt(
    const uint8_t key[NTS_AES_SIV_KEY_LEN],
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t nonce[NTS_AES_SIV_NONCE_LEN],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *output,
    size_t *output_len);

esp_err_t nts_aes_siv_decrypt(
    const uint8_t key[NTS_AES_SIV_KEY_LEN],
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t nonce[NTS_AES_SIV_NONCE_LEN],
    const uint8_t *input,
    size_t input_len,
    uint8_t *plaintext,
    size_t *plaintext_len);