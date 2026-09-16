#pragma once

#include "esp_err.h"

/*
 * Starts the RFC 8915 NTS-KE TLS service on TCP port 4460.
 *
 * Current draft intentionally fails closed until:
 * - TLS 1.3 configuration
 * - ALPN ntske/1
 * - TLS exporter key derivation
 * - AEAD negotiation
 * - NTS-KE record processing
 * - Cookie issuance
 * - interoperability testing
 *
 * are completed and tested.
 */
esp_err_t nts_ke_start(void);
