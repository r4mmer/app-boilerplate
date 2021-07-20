#pragma once

#include <stdbool.h>  // bool

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(bool);

int ui_display_tx_output(action_validate_cb cb);
int ui_display_tx_confirm(void);
int ui_display_xpub_confirm(void);
int ui_display_confirm_address(void);

// /**
//  * Display address on the device and ask confirmation to export.
//  *
//  * @return 0 if success, negative integer otherwise.
//  *
//  */
// int ui_display_address(void);

// /**
//  * Display transaction information on the device and ask confirmation to sign.
//  *
//  * @return 0 if success, negative integer otherwise.
//  *
//  */
// int ui_display_transaction(void);

// /**
//  * Display transaction output information on the device and ask confirmation to continue.
//  *
//  * @return 0 if success, negative integer otherwise.
//  *
//  */
// int ui_display_tx_output(void);
