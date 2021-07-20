#pragma once

#include <stdbool.h>  // bool


void ui_action_tx_confirm(bool choive);
void ui_action_confirm_xpub(bool choive);
void ui_action_confirm_address(bool choive);


// /**
//  * Action for public key validation and export.
//  *
//  * @param[in] choice
//  *   User choice (either approved or rejectd).
//  *
//  */
// void ui_action_validate_xpub(bool choice);

// /**
//  * Action for transaction information validation.
//  *
//  * @param[in] choice
//  *   User choice (either approved or rejectd).
//  *
//  */
// void ui_action_validate_transaction(bool choice);


// void ui_action_validate_tx_output(bool choice);