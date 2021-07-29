#ifndef HATHOR_H
#define HATHOR_H

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool

#include "cx.h"

extern const uint32_t htr_bip44[2];

/**
 * Performs the sha256d (double sha256) of the data
 * 
 * @param[in]  in
 *   Pointer to byte buffer with data.
 * @param[in]  inlen
 *   Lenght of input byte buffer.
 * @param[out] out
 *   Pointer to output byte buffer for address.
 * 
 */
void sha256d(uint8_t *in, size_t inlen, uint8_t *out);

/**
 * Performs the hash160 (sha256 + ripemd160) of the data
 * 
 * @param[in]  in
 *   Pointer to byte buffer with data.
 * @param[in]  inlen
 *   Lenght of input byte buffer.
 * @param[out] out
 *   Pointer to output byte buffer for address.
 *
 */
void hash160(uint8_t *in, size_t inlen, uint8_t *out);

/**
 * Convert public key to address.
 *
 * address = sha256d(public_key)[12:32] (20 bytes)
 *
 * @param[in]  public_key
 *   Pointer to public key.
 * @param[out] out
 *   Pointer to output byte buffer for address.
 *
 */
void address_from_pubkey(cx_ecfp_public_key_t *public_key, uint8_t *out);

void address_from_pubkey_hash(const uint8_t *public_key_hash, uint8_t *out);

/**
 * Derive private key given BIP32 path.
 *
 * @param[out] private_key
 *   Pointer to private key.
 * @param[out] chain_code
 *   Pointer to 32 bytes array for chain code.
 * @param[in]  bip32_path
 *   Pointer to buffer with BIP32 path.
 * @param[in]  bip32_path_len
 *   Number of path in BIP32 path.
 *
 * @throw INVALID_PARAMETER
 *
 */
void derive_private_key(cx_ecfp_private_key_t *private_key,
                        uint8_t chain_code[static 32],
                        const uint32_t *bip32_path,
                        uint8_t bip32_path_len);

void compress_public_key(uint8_t *value);

/**
 * Initialize public key given private key.
 *
 * @param[in]  private_key
 *   Pointer to private key.
 * @param[out] public_key
 *   Pointer to public key.
 * @param[out] raw_public_key
 *   Pointer to raw public key.
 *
 * @throw INVALID_PARAMETER
 *
 */
void init_public_key(cx_ecfp_private_key_t *private_key, cx_ecfp_public_key_t *public_key);

#endif
