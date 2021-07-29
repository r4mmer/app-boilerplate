#include <stdint.h>  // uint*_t

#include "get_address.h"
#include "../globals.h"
#include "../io.h"
#include "../sw.h"
#include "../types.h"
#include "../ui/display.h"
#include "common/buffer.h"

int handler_get_address(buffer_t *cdata) {
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.req_type = CONFIRM_ADDRESS;
    G_context.state = STATE_NONE;

    if (!buffer_read_bip32_path(cdata, &G_context.bip32_path)) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    return ui_display_confirm_address();
}
