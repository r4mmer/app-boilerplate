#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <string.h>   // memmove

#include "os.h"

#include "hathor.h"

// #include "transaction/types.h"

// Path prefix of 44'/280'
const uint32_t htr_bip44[] = { 44 | 0x80000000, HATHOR_BIP44_CODE | 0x80000000 };

void init_bip32_full_path(const uint32_t *in, uint8_t inlen, uint32_t *out) {
    out[0] = htr_bip44[0];
    out[1] = htr_bip44[1];
    for (int i = 0; i < inlen; i++) {
        out[2+i] = in[i];
    }
}

void sha256d(uint8_t *in, size_t inlen, uint8_t *out) {
    cx_sha256_t hash;
    uint8_t buffer[32];

    // sha256 of input to `buffer`
    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, in, inlen, buffer, 32);
    // sha256 of buffer to `out`
    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, buffer, 32, out, 32);
}

void hash160(uint8_t *in, size_t inlen, uint8_t *out) {
    union {
        cx_sha256_t shasha;
        cx_ripemd160_t riprip;
    } u;
    uint8_t buffer[32] = {0};

    cx_sha256_init(&u.shasha);
    cx_hash(&u.shasha.header, CX_LAST, in, inlen, buffer, 32);
    cx_ripemd160_init(&u.riprip);
    cx_hash(&u.riprip.header, CX_LAST, buffer, 32, out, 32);
}

void compress_public_key(uint8_t *value) {
    value[0] = ((value[64] & 1) ? 0x03 : 0x02);
}

void address_from_pubkey_hash(const uint8_t *public_key_hash, uint8_t *out) {
    uint8_t buffer[32] = {0};
    // prepend version
    out[0] = P2PKH_VERSION_BYTE;
    memmove(out+1, public_key_hash, 20);
    // sha256d of above
    sha256d(out, 21, buffer);
    // grab first 4 bytes (checksum)
    memmove(out+21, buffer, 4);
}

void address_from_pubkey(cx_ecfp_public_key_t *public_key, uint8_t *out) {
    uint8_t buffer[32] = {0};
    // compress_public_key
    compress_public_key(public_key->W);
    // hash160
    hash160(public_key->W, 33, buffer);
    // address_from_pubkey_hash
    address_from_pubkey_hash(buffer, out);
}

void derive_private_key(cx_ecfp_private_key_t *private_key,
                        uint8_t chain_code[static 32],
                        const uint32_t *bip32_path,
                        uint8_t bip32_path_len) {
    uint32_t full_path[2+bip32_path_len];
    uint8_t raw_private_key[32] = {0};

    // explicit_bzero(&full_path, sizeof(uint32_t)*(2+bip32_path_len));
    init_bip32_full_path(bip32_path, bip32_path_len, full_path);

    BEGIN_TRY {
        TRY {
            // derive the seed with 44'/280'/$(bip32_path)
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       full_path,
                                       2+bip32_path_len,
                                       raw_private_key,
                                       chain_code);
            // new private_key from raw
            cx_ecfp_init_private_key(CX_CURVE_256K1,
                                     raw_private_key,
                                     sizeof(raw_private_key),
                                     private_key);
        }
        CATCH_OTHER(e) {
            THROW(e);
        }
        FINALLY {
            explicit_bzero(&raw_private_key, sizeof(raw_private_key));
        }
    }
    END_TRY;
}

void init_public_key(cx_ecfp_private_key_t *private_key, cx_ecfp_public_key_t *public_key) {
    // generate corresponding public key
    cx_ecfp_generate_pair(CX_CURVE_256K1, public_key, private_key, 1);
}

// int crypto_sign_message() {
//     cx_ecfp_private_key_t private_key = {0};
//     uint8_t chain_code[32] = {0};
//     uint32_t info = 0;
//     int sig_len = 0;

//     // derive private key according to BIP32 path
//     crypto_derive_private_key(&private_key,
//                               chain_code,
//                               G_context.bip32_path,
//                               G_context.bip32_path_len);

//     BEGIN_TRY {
//         TRY {
//             sig_len = cx_ecdsa_sign(&private_key,
//                                     CX_RND_RFC6979 | CX_LAST,
//                                     CX_SHA256,
//                                     G_context.tx_info.m_hash,
//                                     sizeof(G_context.tx_info.m_hash),
//                                     G_context.tx_info.signature,
//                                     sizeof(G_context.tx_info.signature),
//                                     &info);
//             PRINTF("Signature: %.*H\n", sig_len, G_context.tx_info.signature);
//         }
//         CATCH_OTHER(e) {
//             THROW(e);
//         }
//         FINALLY {
//             explicit_bzero(&private_key, sizeof(private_key));
//         }
//     }
//     END_TRY;

//     if (sig_len < 0) {
//         return -1;
//     }

//     G_context.tx_info.signature_len = sig_len;
//     G_context.tx_info.v = (uint8_t)(info & CX_ECCINFO_PARITY_ODD);

//     return 0;
// }
