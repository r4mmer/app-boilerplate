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