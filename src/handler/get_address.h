#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t

#include "../types.h"
#include "../common/buffer.h"

/**
 * Handler for GET_APP_NAME command. Send APDU response with ASCII
 * encoded name of the application.
 *
 * @see variable APPNAME in Makefile.
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int handler_get_address(buffer_t *cdata);
