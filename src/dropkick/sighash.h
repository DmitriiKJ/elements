#ifndef BITCOIN_DROPKICK_SIGHASH_H
#define BITCOIN_DROPKICK_SIGHASH_H

#include <primitives/dropkick.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>
#include <streams.h>
#include <dropkick/hashes.h>

namespace DropKickSighash
{
    bool BlankedPayloadScript(const DropKickPayloadEntity& payload, CScript& spk_out);

    bool BuildSigningForm(const CTransaction& tx, unsigned int payload_index, const DropKickPayloadEntity& payload, CMutableTransaction& tx_out);

    bool ComputeSighash(const CTransaction& tx, unsigned int payload_index, const DropKickPayloadEntity& payload, uint256& sighash_out);
}

#endif
