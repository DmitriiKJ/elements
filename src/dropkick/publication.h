#ifndef BITCOIN_DROPKICK_PUBLICATION_H
#define BITCOIN_DROPKICK_PUBLICATION_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>
#include <vector>
#include <streams.h>
#include <algorithm>

namespace DropKickPublication 
{
    static constexpr unsigned char MAGIC[4] = {0x44, 0x4b, 0x43, 0x4b};
    static constexpr unsigned int PUSH_SIZE = 36;
    static constexpr unsigned int SCRIPT_SIZE = 38;

    bool ParsePublication(const CScript& spk, uint256& root_out);

    std::vector<uint256> ExtractRoots(const CTransaction& tx);

    bool PublishesRoot(const CTransaction& tx, const uint256& root);

    bool DecodeAnchorTx(const std::vector<unsigned char>& tx_data, CMutableTransaction& tx_out);

    CScript MakePublicationScript(const uint256& root);
}
#endif
