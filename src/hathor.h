#ifndef HATHOR_H
#define HATHOR_H

// opcodes
#define OP_DUP          0x76
#define OP_EQUALVERIFY  0x88
#define OP_HASH160      0xA9
#define OP_CHECKSIG     0xAC


/**
 * All keys that we derive start with path 44'/280'/0'.
 *
 * 80 is Hathor's BIP44 code: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 */
extern const uint32_t htr_bip44[3];

struct tx_output_s {
    uint8_t index; // index of the output on the tx
    uint64_t value;
    // hash160 of the public key
    uint8_t token_data;
    uint8_t pubkey_hash[20];
};
typedef struct tx_output_s tx_output_t;

enum tx_decoder_state_e {
    TX_STATE_ERR = 1,
    TX_STATE_PARTIAL = 1,
    TX_STATE_READY = 1,
    TX_STATE_FINISHED = 1,
};
typedef enum tx_decoder_state_e tx_decoder_state_t;

#endif
