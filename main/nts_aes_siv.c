#include "nts_aes_siv.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"

static esp_err_t psa_to_esp(psa_status_t status)
{
    switch (status) {
    case PSA_SUCCESS:
        return ESP_OK;

    case PSA_ERROR_NOT_SUPPORTED:
        return ESP_ERR_NOT_SUPPORTED;

    case PSA_ERROR_INVALID_ARGUMENT:
    case PSA_ERROR_INVALID_HANDLE:
        return ESP_ERR_INVALID_ARG;

    case PSA_ERROR_BUFFER_TOO_SMALL:
        return ESP_ERR_INVALID_SIZE;

    case PSA_ERROR_INSUFFICIENT_MEMORY:
    case PSA_ERROR_INSUFFICIENT_STORAGE:
        return ESP_ERR_NO_MEM;

    default:
        return ESP_FAIL;
    }
}

static void secure_zero(void *buffer,
                        size_t length)
{
    if (buffer == NULL || length == 0U) {
        return;
    }

    volatile uint8_t *ptr =
        (volatile uint8_t *)buffer;

    while (length-- > 0U) {
        *ptr++ = 0U;
    }
}

static void xor_block(uint8_t output[16],
                      const uint8_t left[16],
                      const uint8_t right[16])
{
    for (size_t i = 0; i < 16U; i++) {
        output[i] = left[i] ^ right[i];
    }
}

static void dbl_block(uint8_t output[16],
                      const uint8_t input[16])
{
    uint8_t carry = 0U;

    for (int i = 15; i >= 0; i--) {
        uint8_t next_carry =
            (uint8_t)((input[i] >> 7) & 0x01U);

        output[i] =
            (uint8_t)((input[i] << 1) | carry);

        carry = next_carry;
    }

    if (carry != 0U) {
        output[15] ^= 0x87U;
    }
}

static bool constant_time_equal(
    const uint8_t *left,
    const uint8_t *right,
    size_t length)
{
    uint8_t difference = 0U;

    for (size_t i = 0; i < length; i++) {
        difference |=
            (uint8_t)(left[i] ^ right[i]);
    }

    return difference == 0U;
}

static esp_err_t import_cmac_key(
    const uint8_t key[16],
    psa_key_id_t *key_id)
{
    if (key == NULL || key_id == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_key_attributes_t attributes =
        PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_AES);

    psa_set_key_bits(
        &attributes,
        128U);

    psa_set_key_usage_flags(
        &attributes,
        PSA_KEY_USAGE_SIGN_MESSAGE);

    psa_set_key_algorithm(
        &attributes,
        PSA_ALG_CMAC);

    psa_status_t status = psa_import_key(
        &attributes,
        key,
        16U,
        key_id);

    psa_reset_key_attributes(&attributes);

    return psa_to_esp(status);
}

static esp_err_t import_ctr_key(
    const uint8_t key[16],
    psa_key_id_t *key_id)
{
    if (key == NULL || key_id == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_key_attributes_t attributes =
        PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_AES);

    psa_set_key_bits(
        &attributes,
        128U);

    psa_set_key_usage_flags(
        &attributes,
        PSA_KEY_USAGE_ENCRYPT |
        PSA_KEY_USAGE_DECRYPT);

    psa_set_key_algorithm(
        &attributes,
        PSA_ALG_CTR);

    psa_status_t status = psa_import_key(
        &attributes,
        key,
        16U,
        key_id);

    psa_reset_key_attributes(&attributes);

    return psa_to_esp(status);
}

static esp_err_t cmac_128(
    const uint8_t key[16],
    const uint8_t *input,
    size_t input_len,
    uint8_t output[16])
{
    psa_key_id_t key_id = 0U;

    esp_err_t err = import_cmac_key(
        key,
        &key_id);

    if (err != ESP_OK) {
        return err;
    }

    size_t mac_len = 0U;

    psa_status_t status = psa_mac_compute(
        key_id,
        PSA_ALG_CMAC,
        input,
        input_len,
        output,
        16U,
        &mac_len);

    (void)psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        secure_zero(output, 16U);
        return psa_to_esp(status);
    }

    if (mac_len != 16U) {
        secure_zero(output, 16U);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t aes_ctr_crypt(
    const uint8_t ctr_key[16],
    const uint8_t siv[16],
    const uint8_t *input,
    size_t input_len,
    uint8_t *output)
{
    if (ctr_key == NULL ||
        siv == NULL ||
        output == NULL ||
        (input == NULL && input_len > 0U)) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_key_id_t key_id = 0U;

    esp_err_t err = import_ctr_key(
        ctr_key,
        &key_id);

    if (err != ESP_OK) {
        return err;
    }

    uint8_t iv[16];
    memcpy(iv, siv, sizeof(iv));

    /*
     * RFC 5297 CTR IV processing:
     * clear the relevant counter bits.
     */
    iv[8] &= 0x7FU;
    iv[12] &= 0x7FU;

    psa_cipher_operation_t operation =
        PSA_CIPHER_OPERATION_INIT;

    psa_status_t status = psa_cipher_encrypt_setup(
        &operation,
        key_id,
        PSA_ALG_CTR);

    if (status == PSA_SUCCESS) {
        status = psa_cipher_set_iv(
            &operation,
            iv,
            sizeof(iv));
    }

    size_t output_len = 0U;

    if (status == PSA_SUCCESS) {
        status = psa_cipher_update(
            &operation,
            input,
            input_len,
            output,
            input_len,
            &output_len);
    }

    size_t finish_len = 0U;

    if (status == PSA_SUCCESS) {
        status = psa_cipher_finish(
            &operation,
            output + output_len,
            input_len - output_len,
            &finish_len);
    }

    psa_cipher_abort(&operation);

    (void)psa_destroy_key(key_id);

    secure_zero(iv, sizeof(iv));

    if (status != PSA_SUCCESS) {
        return psa_to_esp(status);
    }

    if ((output_len + finish_len) != input_len) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t aes_siv_s2v(
    const uint8_t cmac_key[16],
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t nonce[NTS_AES_SIV_NONCE_LEN],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t tag[16])
{
    static const uint8_t zero_block[16] = {0};

    uint8_t d[16];
    uint8_t tmp[16];
    uint8_t cmac_value[16];

    esp_err_t err = cmac_128(
        cmac_key,
        zero_block,
        sizeof(zero_block),
        d);

    if (err != ESP_OK) {
        return err;
    }

    /*
     * S2V associated-data input one:
     * authenticated NTP packet bytes.
     */
    if (associated_data != NULL &&
        associated_data_len > 0U) {
        err = cmac_128(
            cmac_key,
            associated_data,
            associated_data_len,
            cmac_value);

        if (err != ESP_OK) {
            secure_zero(d, sizeof(d));
            return err;
        }

        dbl_block(tmp, d);
        xor_block(d, tmp, cmac_value);
    }

    /*
     * S2V associated-data input two:
     * NTS nonce.
     */
    if (nonce != NULL) {
        err = cmac_128(
            cmac_key,
            nonce,
            NTS_AES_SIV_NONCE_LEN,
            cmac_value);

        if (err != ESP_OK) {
            secure_zero(d, sizeof(d));
            secure_zero(tmp, sizeof(tmp));
            secure_zero(cmac_value,
                        sizeof(cmac_value));

            return err;
        }

        dbl_block(tmp, d);
        xor_block(d, tmp, cmac_value);
    }

    if (plaintext_len >= 16U) {
        uint8_t *buffer = malloc(plaintext_len);

        if (buffer == NULL) {
            secure_zero(d, sizeof(d));
            secure_zero(tmp, sizeof(tmp));
            secure_zero(cmac_value,
                        sizeof(cmac_value));

            return ESP_ERR_NO_MEM;
        }

        memcpy(buffer,
               plaintext,
               plaintext_len);

        for (size_t i = 0; i < 16U; i++) {
            buffer[plaintext_len - 16U + i] ^=
                d[i];
        }

        err = cmac_128(
            cmac_key,
            buffer,
            plaintext_len,
            tag);

        secure_zero(buffer, plaintext_len);
        free(buffer);
    } else {
        uint8_t padded[16] = {0};

        if (plaintext != NULL &&
            plaintext_len > 0U) {
            memcpy(padded,
                   plaintext,
                   plaintext_len);
        }

        padded[plaintext_len] = 0x80U;

        dbl_block(tmp, d);
        xor_block(padded, padded, tmp);

        err = cmac_128(
            cmac_key,
            padded,
            sizeof(padded),
            tag);

        secure_zero(padded, sizeof(padded));
    }

    secure_zero(d, sizeof(d));
    secure_zero(tmp, sizeof(tmp));
    secure_zero(cmac_value, sizeof(cmac_value));

    return err;
}

esp_err_t nts_aes_siv_init(void)
{
    return psa_to_esp(psa_crypto_init());
}

esp_err_t nts_aes_siv_encrypt(
    const uint8_t key[NTS_AES_SIV_KEY_LEN],
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t nonce[NTS_AES_SIV_NONCE_LEN],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *output,
    size_t *output_len)
{
    if (key == NULL ||
        output == NULL ||
        output_len == NULL ||
        (plaintext == NULL && plaintext_len > 0U)) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t required_len =
        NTS_AES_SIV_TAG_LEN + plaintext_len;

    if (*output_len < required_len) {
        *output_len = required_len;
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = nts_aes_siv_init();

    if (err != ESP_OK) {
        return err;
    }

    uint8_t tag[16];

    err = aes_siv_s2v(
        key,
        associated_data,
        associated_data_len,
        nonce,
        plaintext,
        plaintext_len,
        tag);

    if (err != ESP_OK) {
        secure_zero(tag, sizeof(tag));
        return err;
    }

    memcpy(output, tag, NTS_AES_SIV_TAG_LEN);

    err = aes_ctr_crypt(
        &key[16],
        tag,
        plaintext,
        plaintext_len,
        &output[NTS_AES_SIV_TAG_LEN]);

    secure_zero(tag, sizeof(tag));

    if (err != ESP_OK) {
        secure_zero(output, required_len);
        return err;
    }

    *output_len = required_len;

    return ESP_OK;
}

esp_err_t nts_aes_siv_decrypt(
    const uint8_t key[NTS_AES_SIV_KEY_LEN],
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t nonce[NTS_AES_SIV_NONCE_LEN],
    const uint8_t *input,
    size_t input_len,
    uint8_t *plaintext,
    size_t *plaintext_len)
{
    if (key == NULL ||
        input == NULL ||
        plaintext == NULL ||
        plaintext_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (input_len < NTS_AES_SIV_TAG_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t ciphertext_len =
        input_len - NTS_AES_SIV_TAG_LEN;

    if (*plaintext_len < ciphertext_len) {
        *plaintext_len = ciphertext_len;
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = nts_aes_siv_init();

    if (err != ESP_OK) {
        return err;
    }

    const uint8_t *received_tag = input;

    const uint8_t *ciphertext =
        &input[NTS_AES_SIV_TAG_LEN];

    err = aes_ctr_crypt(
        &key[16],
        received_tag,
        ciphertext,
        ciphertext_len,
        plaintext);

    if (err != ESP_OK) {
        secure_zero(plaintext, ciphertext_len);
        return err;
    }

    uint8_t expected_tag[16];

    err = aes_siv_s2v(
        key,
        associated_data,
        associated_data_len,
        nonce,
        plaintext,
        ciphertext_len,
        expected_tag);

    if (err != ESP_OK) {
        secure_zero(plaintext, ciphertext_len);
        secure_zero(expected_tag,
                    sizeof(expected_tag));

        return err;
    }

    bool valid = constant_time_equal(
        received_tag,
        expected_tag,
        sizeof(expected_tag));

    secure_zero(expected_tag,
                sizeof(expected_tag));

    if (!valid) {
        secure_zero(plaintext, ciphertext_len);
        return ESP_ERR_INVALID_CRC;
    }

    *plaintext_len = ciphertext_len;

    return ESP_OK;
}