#include <stdint.h>
#include <stdbool.h>

#include "dispatcher.h"
#include "../constants.h"
#include "../globals.h"
#include "../types.h"
#include "../io.h"
#include "../sw.h"
#include "../common/buffer.h"
#include "../handler/get_version.h"
#include "../handler/get_address.h"
#include "../handler/get_xpub.h"
#include "../handler/sign_tx.h"

int apdu_dispatcher(const command_t *cmd) {
    if (cmd->cla != CLA) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }

    buffer_t buf = {0};

    switch (cmd->ins) {
        case GET_VERSION:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return handler_get_version();
        case GET_ADDRESS:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            if (!cmd->data) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_get_address(&buf);
        case GET_XPUB:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            if (!cmd->data) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_get_xpub(&buf);
        case SIGN_TX:
            if (cmd->p1 > SIGN_TX_P1_MAX ||                                     //
                (cmd->p1 == SIGN_TX_P1_SIGN && cmd->p2 != SIGN_TX_P2_SIGN) ||   //
                (cmd->p1 == SIGN_TX_P1_DONE && cmd->p2 != SIGN_TX_P2_DONE)) {   //
                return io_send_sw(SW_WRONG_P1P2);
            }
            // if ((cmd->p1 == P1_START && cmd->p2 != P2_MORE) ||  //
            //     cmd->p1 > P1_MAX ||                             //
            //     (cmd->p2 != P2_LAST && cmd->p2 != P2_MORE)) {
            //     return io_send_sw(SW_WRONG_P1P2);
            // }

            // XXX: maybe validate data_len for each command?
            // if (!cmd->data) {
            //     return io_send_sw(SW_WRONG_DATA_LENGTH);
            // }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            // TODO: new handler call sign
            return handler_sign_tx(&buf, (sing_tx_stage_e) cmd->p1, cmd->p2);
            // return handler_sign_tx(&buf, cmd->p1, (bool) (cmd->p2 & 0x80));
        default:
            return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
}
