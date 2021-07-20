#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "../common/buffer.h"
#include "types.h"

/**
 * Handler for SIGN_TX command. If successfully parse BIP32 path
 * and transaction, sign transaction and send APDU response.
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int handler_sign_tx(buffer_t *cdata, sing_tx_stage_e stage, uint8_t chunk);
