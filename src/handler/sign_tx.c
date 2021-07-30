#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // explicit_bzero, memmove

#include "os.h"
#include "cx.h"

#include "sign_tx.h"

#include "../hathor.h"
#include "../sw.h"
#include "../globals.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "../common/buffer.h"
#include "../common/read.h"
#include "../transaction/types.h"
#include "../transaction/deserialize.h"


bool verify_address(tx_output_t output, uint32_t *bip32_path, uint8_t bip32_len) {
    uint8_t hash[PUBKEY_HASH_LEN];
    cx_ecfp_public_key_t public_key;
    cx_ecfp_private_key_t private_key;
    uint8_t chain_code[32];

    derive_private_key(&private_key, chain_code, bip32_path, bip32_len);
    init_public_key(&private_key, &public_key);
    compress_public_key(public_key.W);
    hash160(public_key.W, 33, hash);

    // erase data
    explicit_bzero(&private_key, sizeof(private_key));
    explicit_bzero(&public_key, sizeof(public_key));
    explicit_bzero(&chain_code, sizeof(chain_code));

    // 0 means equals
    return memcmp(hash, output.pubkey_hash, PUBKEY_HASH_LEN) == 0;
}

void read_change_output_info(buffer_t *cdata) {
    uint8_t buffer[MAX_BIP32_PATH * 4 + 1] = {0};
    uint8_t tmp;

    // 1 byte for has_change_output and bip32 path len
    if (!buffer_read_u8(cdata, &tmp)) {
        THROW(SW_WRONG_DATA_LENGTH);
    }

    // The first bit indicates the existence of a change output
    G_context.tx_info.has_change_output = (bool) tmp & 0x80;

    if (G_context.tx_info.has_change_output) {
        // 1 byte for change output index
        if (!buffer_read_u8(cdata, &G_context.tx_info.change_output_index)) {
            THROW(SW_WRONG_DATA_LENGTH);
        }
        // the remainder of the first byte was used to represent the bip32 path length of the change path
        buffer[0] = tmp & 0x0F;
        if(buffer[0] > MAX_BIP32_PATH || !buffer_move(cdata, buffer+1, 4*buffer[0])) {
            THROW(SW_WRONG_DATA_LENGTH);
        }

        buffer_t bufdata = {
            .ptr = buffer,
            .size=(size_t) ( 1 + ( 4 * buffer[0] ) ),
            .offset = 0
        };

        // buffer holds the serialized bip32 path that was read from cdata
        if (!buffer_read_bip32_path(&bufdata, &G_context.tx_info.change_bip32_path)) THROW(SW_WRONG_DATA_LENGTH);
    }
}

void read_tx_data(buffer_t *cdata) {
    if (!(buffer_read_u16(cdata, &G_context.tx_info.tx_version, BE) && // read version bytes (Big Endian)
        buffer_read_u8(cdata, &G_context.tx_info.remaining_tokens) && // read number of tokens, inputs and outputs, respectively
        buffer_read_u8(cdata, &G_context.tx_info.remaining_inputs) &&
        buffer_read_u8(cdata, &G_context.tx_info.outputs_len))) {
        // if an error occurs reading
        THROW(SW_WRONG_DATA_LENGTH);
    }

    if (G_context.tx_info.outputs_len > MAX_NUM_TX_OUTPUTS) {
        THROW(SW_TX_PARSING_FAIL);
    }
}

void sighash_all_hash(buffer_t *cdata) {
    // cx_hash returns the size of the hash after adding the data, we can safely ignore it

    cx_hash(
        &G_context.tx_info.sha256.header,   // hash context pointer
        0,                                  // mode (supports: CX_LAST)
        cdata->ptr + cdata->offset,         // Input data to add to current hash
        cdata->size - cdata->offset,        // Length of input data
        NULL, 0);                           // output (if flag CX_LAST was set)
}


bool sign_tx_with_key() {
    // the bip32 path and bip32 path length should be on the global context when calling this method.

    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key = {0};

    uint8_t chain_code[32];

    derive_private_key(&private_key, chain_code, G_context.bip32_path.path, G_context.bip32_path.length);
    init_public_key(&private_key, &public_key);

    if (G_context.tx_info.sighash_all[0] == '\0') {
        // finish sha256 from data
        cx_hash(&G_context.tx_info.sha256.header, CX_LAST, G_context.tx_info.sighash_all, 0, G_context.tx_info.sighash_all, 32);
        // now get second sha256
        cx_sha256_init(&G_context.tx_info.sha256);
        cx_hash(&G_context.tx_info.sha256.header, CX_LAST, G_context.tx_info.sighash_all, 32, G_context.tx_info.sighash_all, 32);
    }

    uint8_t out[256] = {0};
    size_t sig_size = cx_ecdsa_sign(&private_key, CX_LAST | CX_RND_RFC6979, CX_SHA256, G_context.tx_info.sighash_all, 32, out, 256, NULL);

    explicit_bzero(&private_key, sizeof(private_key));
    explicit_bzero(&public_key, sizeof(public_key));

    // exchange signature
    // io_send_response < 0 means faillure
    return io_send_response(&(const buffer_t){.ptr = out, .size = sig_size, .offset = 0}, SW_OK) >= 0;
}

void _decode_next_element() {
    // test if there are more tokens, inputs and outputs in this order
    // if there are, try to read from buffer
    // if any are incomplete, inform caller to send more data 
    if (G_context.tx_info.remaining_tokens > 0) {
        // can read token?
        if (G_context.tx_info.buffer_len < TOKEN_UID_LEN) {
            // still decoding tokens, but this one was divided between calls 
            THROW(TX_STATE_PARTIAL);
        }
        // for now we ignore it
        G_context.tx_info.remaining_tokens--;
        G_context.tx_info.buffer_len -= TOKEN_UID_LEN;
        G_context.tx_info.elem_type = ELEM_TOKEN_UID;
        memmove(G_context.tx_info.buffer, G_context.tx_info.buffer + TOKEN_UID_LEN, G_context.tx_info.buffer_len);
    } else if(G_context.tx_info.remaining_inputs > 0) {
        // can read input?
        if (G_context.tx_info.buffer_len < TX_INPUT_LEN) {
            THROW(TX_STATE_PARTIAL);
        }
        // we require input to have no data, since we are signing all data received (sighash_all must have no data)
        // other than this check, we can ignore the input
        uint16_t input_data_len = read_u16_be(G_context.tx_info.buffer, 33);
        if (input_data_len > 0) {
            THROW(TX_STATE_ERR);
        }
        // reading input
        G_context.tx_info.remaining_inputs--;
        G_context.tx_info.buffer_len -= TX_INPUT_LEN;
        G_context.tx_info.elem_type = ELEM_INPUT;
        memmove(G_context.tx_info.buffer, G_context.tx_info.buffer + TX_INPUT_LEN, G_context.tx_info.buffer_len);
    } else if (G_context.tx_info.current_output < G_context.tx_info.outputs_len) {
        // read output
        size_t output_len = parse_output(G_context.tx_info.buffer, G_context.tx_info.buffer_len, &G_context.tx_info.decoded_output);
        G_context.tx_info.decoded_output.index = G_context.tx_info.current_output;
        G_context.tx_info.elem_type = ELEM_OUTPUT;
        // move buffer
        G_context.tx_info.buffer_len -= output_len;
        memmove(G_context.tx_info.buffer, G_context.tx_info.buffer + output_len, output_len); 
        G_context.tx_info.current_output++;
    } else {
        // we reached the end of the data we should read, the buffer should be empty
        // if the buffer is not empty something went wrong
        if (G_context.tx_info.buffer_len > 0) {
            THROW(TX_STATE_ERR);
        }
        THROW(TX_STATE_FINISHED);
    }

    switch (G_context.tx_info.elem_type)
    {
    case ELEM_TOKEN_UID:
        // not displaying token uid
        break;
    case ELEM_INPUT:
        // not displaying inputs
        break;
    case ELEM_OUTPUT:
        // check if this is the change output
        if (
            G_context.tx_info.has_change_output &&
            G_context.tx_info.change_output_index == G_context.tx_info.decoded_output.index) {
                // verify change
                if (!verify_address(
                    G_context.tx_info.decoded_output,
                    G_context.tx_info.change_bip32_path.path,
                    G_context.tx_info.change_bip32_path.length)) {
                    THROW(TX_STATE_ERR);
                }
        } else {
            THROW(TX_STATE_READY);
        }
        break;
    }
}

tx_decoder_state_e decode_next_element() {
    volatile tx_decoder_state_e result;
    BEGIN_TRY {
        TRY {
            for (;;) _decode_next_element();
        }
        CATCH_OTHER(e) {
            result = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    return result;
}

// Callback of button to confirm current decoded_output
// Will decode and display next if ready
void confirm_tx_cb(bool choice) {
    if (!choice) {
        // cancel everything if user denies an output
        explicit_bzero(&G_context, sizeof(G_context));
        io_send_sw(SW_DENY);
        return;
    }
    // decode next output and redisplay
    switch (decode_next_element())
    {
    case TX_STATE_ERR:
        io_send_sw(SW_INVALID_TX);
        explicit_bzero(&G_context, sizeof(G_context));
        ui_menu_main();
        return;
    case TX_STATE_PARTIAL:
        // request more data with SW_OK
        // THROW(SW_OK);
        io_send_sw(SW_OK);
        return;
    case TX_STATE_READY:
        // display new decoded_output
        ui_display_tx_output(&confirm_tx_cb);
        return;
    case TX_STATE_FINISHED:
        ui_display_tx_confirm();
        return;
    }
}

void init_sign_tx_ctx() {
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.req_type = CONFIRM_TRANSACTION; /// SIGN_TX

    G_context.tx_info.buffer_len = 0;
    G_context.state = STATE_RECV_DATA;
    G_context.tx_info.has_change_output = false;
    G_context.tx_info.current_output = 0;

    cx_sha256_init(&G_context.tx_info.sha256);
    G_context.tx_info.sighash_all[0] = '\0';
}

bool receive_data(buffer_t *cdata, uint8_t chunk) {
    // The transaction will be divided into chunks of data
    // each chunk will be numbered, chunk==0 means this is the start of the data.
    if (chunk == 0) {
        if (G_context.state == STATE_RECV_DATA) {
            // sent first chunk twice? return error
            THROW(SW_BAD_STATE);
        }

        init_sign_tx_ctx();
        // read change output and sighash
        read_change_output_info(cdata);
        // sighash_all_hash won't move cdata.offset
        sighash_all_hash(cdata);
        read_tx_data(cdata);

        if(!buffer_move(cdata, G_context.tx_info.buffer, cdata->size - cdata->offset)) {
            THROW(SW_WRONG_DATA_LENGTH);
        }
        G_context.tx_info.buffer_len = cdata->size - cdata->offset;
    } else {
        // copy sighash_all data to sha256 context
        sighash_all_hash(cdata);
        // move the same data to decode buffer
        if(!buffer_move(cdata, G_context.tx_info.buffer, cdata->size - cdata->offset)) {
            THROW(SW_WRONG_DATA_LENGTH);
        }
        G_context.tx_info.buffer_len += cdata->size - cdata->offset;
    }

    switch (decode_next_element())
    {
    case TX_STATE_ERR:
        io_send_sw(SW_INVALID_TX);
        explicit_bzero(&G_context, sizeof(G_context));
        ui_menu_main();
        return true;
    case TX_STATE_PARTIAL:
        // request more data with SW_OK
        THROW(SW_OK);
    case TX_STATE_READY:
        ui_display_tx_output(&confirm_tx_cb);
        return true;
    case TX_STATE_FINISHED:
        ui_display_tx_confirm();
        return true;
    }
    return false;
}

int handler_sign_tx(buffer_t *cdata, sing_tx_stage_e stage, uint8_t chunk) {
    // switch(stage) actions for each stage
    // - SIGN_TX_STAGE_DONE: signals the end of the call
    // - SIGN_TX_STAGE_SIGN: TX was received and approved by user, caller requests signing
    // - SIGN_TX_STAGE_DATA: Receiving TX in chunks
    switch (stage) {
        case SIGN_TX_STAGE_DONE:
            // Caller is done with this request, cleanup and return SW_OK.
            explicit_bzero(&G_context, sizeof(G_context));
            G_context.state = STATE_NONE;
            return io_send_sw(SW_OK);

        case SIGN_TX_STAGE_SIGN:
            // Caller passes the bip32 path of the key needed to sign the request
            if (G_context.state != STATE_APPROVED) {
                // The user must have approved already
                return io_send_sw(SW_BAD_STATE);
            }

            if (!buffer_read_bip32_path(cdata, &G_context.bip32_path)) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }

            // sign with input key and return SW_OK
            if(!sign_tx_with_key()) return -1;
            break;

        case SIGN_TX_STAGE_DATA:
            // Caller will pass the transaction and metadata needed to approve and sign.
            if (G_context.state == STATE_APPROVED) {
                // cannot receive more data after user approval
                ui_menu_main();
                return io_send_sw(SW_BAD_STATE);
            }
            if(!receive_data(cdata, chunk)) return -1;
            break;

        default:
            ui_menu_main();
            return io_send_sw(SW_BAD_STATE);
    }

    return 0;
}