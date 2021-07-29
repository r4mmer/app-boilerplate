#pragma once

#include "../common/buffer.h"

/**
 * Handler for GET_APP_NAME command. Send APDU response with ASCII
 * encoded name of the application.
 *
 * @param[in] cdata
 *   Buffer with data from caller.
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int handler_get_address(buffer_t *cdata);
