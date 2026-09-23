#ifndef BITCOIN_DROPKICK_PAYLOAD_H
#define BITCOIN_DROPKICK_PAYLOAD_H

#include <primitives/dropkick.h>
#include <primitives/transaction.h>

namespace DropKickPayload
{
    bool HasPayloadOutput(const CTransaction& tx);

    bool ExtractPayload(const CTransaction& tx, unsigned int& index_out, DropKickPayloadEntity& payload_out);
}

#endif
