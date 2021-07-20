#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t

#include "../types.h"
#include "../common/buffer.h"

int handler_get_xpub(buffer_t *cdata);
