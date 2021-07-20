#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

// #include <stdbool.h>  // bool
#include <stdint.h>
#include <string.h>

#include "os.h"
#include "ux.h"
#include "glyphs.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
// #include "../io.h"
#include "../sw.h"
#include "action/validate.h"
// #include "../transaction/types.h"
// #include "../common/bip32.h"
#include "../common/format.h"

#include "../hathor.h"

// #include "../types.h"
#include "../common/base58.h"

static action_validate_cb g_validate_callback;
static char g_amount[30];
static char g_bip32_path[60];
static char g_output_index[10];
static char g_address[B58_ADDRESS_LEN];


// Step with title/text for BIP32 path
UX_STEP_NOCB(ux_display_path_step,
             bnnn_paging,
             {
                 .title = "Path",
                 .text = g_bip32_path,
             });
// Step with title/text for address
UX_STEP_NOCB(ux_display_address_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = g_address,
             });
// Step with title/text for amount
UX_STEP_NOCB(ux_display_amount_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = g_amount,
             });
// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(true),
           {
               &C_icon_validate_14,
               "Approve",
           });
// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(false),
           {
               &C_icon_crossmark,
               "Reject",
           });

UX_STEP_NOCB(ux_display_confirm_addr_step, pnn, {&C_icon_eye, "Confirm", "Address"});

UX_STEP_NOCB(ux_display_review_output_step,
             pnn,
             {
                 &C_icon_eye,
                 "Output",
                 g_output_index,
             });

UX_STEP_NOCB(ux_display_confirm_sign_step,
             pnn,
             {
                 &C_icon_eye,
                 "Send",
                 "Transaction?",
             });

UX_STEP_NOCB(ux_display_confirm_step,
             pnn,
             {
                 &C_icon_eye,
                 "Confirm",
                 "access?",
             });

// sign_tx confirm output
UX_FLOW(ux_display_tx_output_flow,
        &ux_display_review_output_step, // Output <curr>/<total>
        &ux_display_address_step,       // pubkey_hash
        &ux_display_amount_step,        // HTR <value>
        &ux_display_approve_step,       // accept => decode next component and redisplay if needed
        &ux_display_reject_step);       // reject => return error

int ui_display_tx_output(action_validate_cb cb) {
    // set g_output_index
    uint8_t total_outputs = G_context.tx_info.outputs_len;
    uint8_t fake_output_index = G_context.tx_info.decoded_output.index + 1;
    if (G_context.tx_info.has_change_output) {
        total_outputs--;
        if (G_context.tx_info.decoded_output.index > G_context.tx_info.change_output_index) {
            fake_output_index--;
        }
    }
    itoa(fake_output_index, g_output_index, 10);
    uint8_t len = strlen(g_output_index);
    g_output_index[len++] = '/';
    itoa(total_outputs, g_output_index+len, 10);

    // set g_address
    memset(g_address, 0, sizeof(g_address));
    char b58address[B58_ADDRESS_LEN] = {0};
    uint8_t address[ADDRESS_LEN] = {0};
    address_from_pubkey_hash(G_context.tx_info.decoded_output.pubkey_hash, address);
    base58_encode(address, ADDRESS_LEN, b58address, B58_ADDRESS_LEN);
    snprintf(g_address, sizeof(g_address), "%.*H", sizeof(b58address), b58address);

    // set g_ammount (HTR value)
    memset(g_amount, 0, sizeof(g_amount));
    strcpy(g_amount, "HTR ");
    format_value(G_context.tx_info.decoded_output.value, g_amount+4);

    g_validate_callback = cb; // decode and show next until need more
    ux_flow_init(0, ux_display_tx_output_flow, NULL);

    return 0;
}

/* FLOW to display confirm sign tx:
 *  #1 screen : eye icon + "Send Transaction?"
 *  #2 screen : approve button
 *  #3 screen : reject button
 */
UX_FLOW(ux_display_confirm_tx_flow,
        &ux_display_confirm_sign_step,  // -> <eye> Send Transaction?
        &ux_display_approve_step,       // -> return SW_OK
        &ux_display_reject_step);       // -> return reject

int ui_display_tx_confirm() {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    g_validate_callback = &ui_action_tx_confirm; // set state_approved and send sw_ok

    ux_flow_init(0, ux_display_confirm_tx_flow, NULL);

    return 0;
}

// Get XPUB: ui_display_xpub_confirm

/* FLOW to display confirm access to XPUB:
 *  #1 screen: eye icon + "Confirm Access?"
 *  #2 screen: display BIP32 Path
 *  #3 screen: approve button
 *  #4 screen: reject button
 */
UX_FLOW(ux_display_xpub_flow,
        &ux_display_confirm_step,  // <eye> Confirm Access?
        &ux_display_path_step,          // bip32 path
        &ux_display_approve_step,       // accept => send xpub in response
        &ux_display_reject_step);       // reject => return error

int ui_display_xpub_confirm() {
    if (G_context.req_type != CONFIRM_XPUB || G_context.state != STATE_NONE) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }
    uint32_t full_path[MAX_BIP32_PATH];
    init_bip32_full_path(G_context.bip32_path.path, G_context.bip32_path.length, full_path);

    memset(g_bip32_path, 0, sizeof(g_bip32_path));

    if (!bip32_path_format(full_path,
                           2+G_context.bip32_path.length,
                           g_bip32_path,
                           sizeof(g_bip32_path))) {
        return io_send_sw(SW_DISPLAY_BIP32_PATH_FAIL);
    }

    g_validate_callback = &ui_action_confirm_xpub; // send xpub from bip32 path

    ux_flow_init(0, ux_display_xpub_flow, NULL);

    return 0;
}

// Get Address: ui_display_confirm_address

/* FLOW to display confirm address:
 *  #1 screen: eye icon + "Confirm Address?"
 *  #2 screen: display BIP32 Path
 *  #3 screen: display address
 *  #4 screen: approve button
 *  #5 screen: reject button
 */
UX_FLOW(ux_display_address_flow,
        &ux_display_confirm_addr_step,  // <eye> Confirm Address
        &ux_display_path_step,          // bip32 path
        &ux_display_address_step,       // address
        &ux_display_approve_step,       // accept => return ok
        &ux_display_reject_step);       // reject => return error

int ui_display_confirm_address() {
    if (G_context.req_type != CONFIRM_ADDRESS || G_context.state != STATE_NONE) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }
    uint32_t full_path[MAX_BIP32_PATH];
    init_bip32_full_path(G_context.bip32_path.path, G_context.bip32_path.length, full_path);

    memset(g_bip32_path, 0, sizeof(g_bip32_path));

    if (!bip32_path_format(full_path,
                           2+G_context.bip32_path.length,
                           g_bip32_path,
                           sizeof(g_bip32_path))) {
        return io_send_sw(SW_DISPLAY_BIP32_PATH_FAIL);
    }

    memset(g_address, 0, sizeof(g_address));
    uint8_t address[ADDRESS_LEN] = {0};
    char b58address[B58_ADDRESS_LEN] = {0};
    // hash raw_public_key
    uint8_t buffer[32] = {0};
    // compress_public_key
    uint8_t compressed_pubkey[65];
    memmove(compressed_pubkey, G_context.pk_info.raw_public_key, 65);
    compress_public_key(compressed_pubkey);
    // hash160
    hash160(compressed_pubkey, 33, buffer);
    address_from_pubkey_hash(buffer, address);
    base58_encode(address, ADDRESS_LEN, b58address, B58_ADDRESS_LEN);
    snprintf(g_address, sizeof(g_address), "%.*H", sizeof(b58address), b58address);

    g_validate_callback = &ui_action_confirm_address;

    ux_flow_init(0, ux_display_address_flow, NULL);

    return 0;
}
