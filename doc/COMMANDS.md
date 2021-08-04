# Hathor commands

## Overview

| Command name | INS | Description |
| --- | --- | --- |
| `GET_VERSION` | 0x03 | Get application version as 'H', 'T', 'R', `MAJOR`, `MINOR`, `PATCH` |
| `GET_ADDRESS` | 0x04 | Confirm the address on a given BIP32 path with the user |
| `GET_XPUB` | 0x05 | Get xpub data given BIP32 path |
| `SIGN_TX` | 0x06 | Sign transaction |

## GET_VERSION

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x03 | 0x00 | 0x00 | 0x00 | - |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| 6 | 0x9000 | `'HTR'` \|\| `MAJOR (1)` \|\| `MINOR (1)` \|\| `PATCH (1)` |

## GET_ADDRESS

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x04 | 0x00 | 0x00 | 1 + 4n | `len(bip32_path) (1)` \|\|<br> `bip32_path{1} (4)` \|\|<br>`...` \|\|<br>`bip32_path{n} (4)` |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| 0 | 0x9000 | - |

## GET_XPUB

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x05 | 0x00 | 0x00 | 1 + 4n | `len(bip32_path) (1)` \|\|<br> `bip32_path{1} (4)` \|\|<br>`...` \|\|<br>`bip32_path{n} (4)` |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `raw_public_key (65)` \|\|<br> `chain_code (32)`  \|\|<br> `fingerprint (4)` |

## SIGN_TX

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x06 | 0x00-0x02 (stage) | 0x00-0xFF (chunk index) | var | see below |

| P1 | Stage | Cdata |
| --- | --- | --- |
| 0x00 | data | `change info (var)` \|\|<br> `TX version (2)` \|\|<br> `number of tokens (1)` \|\|<br> `number of inputs (1)` \|\|<br> `number of outputs (1)` \|\|<br> `tokens (32 * num_token)` \|\|<br> `inputs (35 * num_inputs)` \|\|<br> `outputs (var)` |
| 0x01 | sign | `len(bip32_path) (1)` \|\|<br> `bip32_path{1} (4)` \|\|<br>`...` \|\|<br>`bip32_path{n} (4)` |
| 0x02 | end | - |

Change info:

| Have change output | Cdata |
| --- | --- |
| `false` | `0x00 (1)` |
| `true` | `first bit on + len(change_bip32_path) (1)` \|\|<br> `change output index (1)` \|\|<br> `bip32_path{1} (4)` \|\|<br>`...` \|\|<br>`bip32_path{n} (4)` |

- `len(change_bip32_path)` can have a low hard limit (i.e. 5) so we can interpret this only with 4 bits, and since `has_change_output` is a boolean, we can use a byte to represent both.
    - The byte: `A____ BBBB` where A is the `has_change_output` and B is the `len(bip_32_path)`
- `change_output_index`: omit if `has_change_output` is false
- The next 4c bytes (c being `len(change_bip_32_path)`) are the bip32_path.


### Response

| Stage | Response length (bytes) | SW | RData |
| --- | --- | --- | --- |
| data | 0 | 0x9000 | - |
| sign | var | 0x9000 | `signature (var)` |
| end | 0 | 0x9000 | - |

On the `data` and `sign` stages each call receives a `SW_OK` when processing is done (or upon user confirmation) so the caller can send more data.

## Status Words

| SW | SW name | Description |
| --- | --- | --- |
| 0x6985 | `SW_DENY` | Rejected by user |
| 0x6A86 | `SW_WRONG_P1P2` | Either `P1` or `P2` is incorrect |
| 0x6A87 | `SW_WRONG_DATA_LENGTH` | `Lc` or minimum APDU lenght is incorrect |
| 0x6D00 | `SW_INS_NOT_SUPPORTED` | No command exists with `INS` |
| 0x6E00 | `SW_CLA_NOT_SUPPORTED` | Bad `CLA` used for this application |
| 0xB000 | `SW_WRONG_RESPONSE_LENGTH` | Wrong response lenght (buffer size problem) |
| 0xB001 | `SW_DISPLAY_BIP32_PATH_FAIL` | BIP32 path conversion to string failed |
| 0xB002 | `SW_DISPLAY_ADDRESS_FAIL` | Address conversion to string failed |
| 0xB003 | `SW_DISPLAY_AMOUNT_FAIL` | Amount conversion to string failed |
| 0xB004 | `SW_WRONG_TX_LENGTH` | Wrong raw transaction lenght |
| 0xB005 | `SW_TX_PARSING_FAIL` | Failed to parse raw transaction |
| 0xB006 | `SW_TX_HASH_FAIL` | Failed to compute hash digest of raw transaction |
| 0xB007 | `SW_BAD_STATE` | Security issue with bad state |
| 0xB008 | `SW_SIGNATURE_FAIL` | Signature of raw transaction failed |
| 0x9000 | `OK` | Success |
