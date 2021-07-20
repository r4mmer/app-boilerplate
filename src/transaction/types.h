#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "opcodes.h"

#include "../common/bip32.h"

#define ADDRESS_LEN  25
#define B58_ADDRESS_LEN  34
#define TOKEN_UID_LEN 32
#define TX_INPUT_LEN 35

typedef enum {
    PARSING_OK = 1,
    NONCE_PARSING_ERROR = -1,
    TO_PARSING_ERROR = -2,
    VALUE_PARSING_ERROR = -3,
    MEMO_LENGTH_ERROR = -4,
    MEMO_PARSING_ERROR = -5,
    MEMO_ENCODING_ERROR = -6,
    WRONG_LENGTH_ERROR = -7
} parser_status_e;

typedef enum {
    TX_STATE_ERR = 1,
    TX_STATE_PARTIAL = 2,
    TX_STATE_READY = 3,
    TX_STATE_FINISHED = 4,
} tx_decoder_state_e;

typedef enum {
    ELEM_TOKEN_UID,
    ELEM_INPUT,
    ELEM_OUTPUT,
} tx_decoder_elem_t;

typedef enum {
    SIGN_TX_STAGE_DATA = 0,
    SIGN_TX_STAGE_SIGN = 1,
    SIGN_TX_STAGE_DONE = 2
} sing_tx_stage_e;

/**
 * Structure for transaction output
 */
typedef struct {
    uint8_t index;
    uint64_t value;
    // hash160 of pubkey
    uint8_t token_data;
    uint8_t pubkey_hash[20]; // add pubkey_hash len to constants?
} tx_output_t;

// tx_input_t?

typedef struct {
    bool has_change;
    uint8_t change_output_index;
    uint8_t change_bip32_len;
    uint32_t change_bip32_path[MAX_BIP32_PATH];
    uint8_t outputs_len;
    tx_output_t outputs[100]; // max_outputs on constants?
    uint8_t tokens_len;
} tx_t;

typedef struct {
    uint64_t nonce;     /// nonce (8 bytes)
    uint64_t value;     /// amount value (8 bytes)
    uint8_t *to;        /// pointer to address (20 bytes)
    uint8_t *memo;      /// memo (variable length)
    uint64_t memo_len;  /// length of memo (8 bytes)
} transaction_t;