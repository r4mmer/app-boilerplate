#include <stdbool.h>  // bool
#include <string.h>   // memset, explicit_bzero, memmove


#include "deserialize.h"

#include "os.h" // THROW
// #include "cx.h"
#include "../sw.h"
// #include "../common/read.h"
#include "../common/buffer.h"

/**
 * XXX: considering only P2PKH, without timelock
 * Validates that a script has the format of P2PKH. Throws an exception if doesn't.
 * P2PKH scripts have the format:
 *   [OP_DUP, OP_HASH160, pubkey_hash_len, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
 */
void validate_p2pkh_script(buffer_t *in) {
    uint8_t p2pkh[] = {OP_DUP, OP_HASH160, 20, OP_EQUALVERIFY, OP_CHECKSIG};
    if (in->size - in->offset < 25) {
        THROW(SW_TX_PARSING_FAIL);
    }

    if (memcmp(p2pkh, in->ptr, 3) != 0 || memcmp(p2pkh+3, in->ptr+23, 2) != 0) {
        THROW(SW_TX_PARSING_FAIL);
    }
}

void parse_output_value(buffer_t *buf, uint64_t *value) {
    // if first bit is 1 value has length 8 bytes, otherwise it's 4 bytes 
    bool flag = (bool)(0x80 & buf->ptr[0]);
    if (flag) {
        uint64_t tmp = 0;
        buffer_read_u64(buf, &tmp, BE);
        // To use the first bit to indicate length of 8 bytes
        // we serialized the negative value of the 8 byte int so we need to correct it
        tmp = (-1)*tmp;
        *value = tmp;
    } else {
        uint32_t tmp = 0;
        buffer_read_u32(buf, &tmp, BE);
        // we don't need to correct anything 
        *value = tmp;
    }
}

size_t parse_output(uint8_t *in, size_t inlen, tx_output_t *output) {
    uint16_t script_len;
    buffer_t buf = {.ptr = in, .size = inlen, .offset=0};
    parse_output_value(&buf, &output->value);

    // read token data and script length
    if (!(
        buffer_read_u8(&buf, &output->token_data) &&
        buffer_read_u16(&buf, &script_len, BE)
        )) {
            THROW(SW_TX_PARSING_FAIL); // or wrong data length?
        }

    // validate script and extract pubkey hash
    validate_p2pkh_script(&buf);
    // validate already asserted the length for this extraction
    memmove(output->pubkey_hash, buf.ptr + buf.offset + 3, 20);
    if(!buffer_seek_cur(&buf, script_len)) {
        THROW(SW_TX_PARSING_FAIL);
    }

    // size of extracted data
    return buf.offset;
}
