#ifndef BITCOIN_DROPKICK_VALIDATION_H
#define BITCOIN_DROPKICK_VALIDATION_H

#include <primitives/dropkick.h>
#include <primitives/transaction.h>
#include <dropkick/hashes.h>
#include <dropkick/publication.h>
#include <dropkick/commitment.h>
#include <dropkick/statement.h>
#include <dropkick/sighash.h>
#include <dropkick/payload.h>
#include <script/script.h>
#include <uint256.h>
#include <algorithm>
#include <string>
#include <vector>
#include <confidential_validation.h>

namespace DropKickValidation
{
    class ChainAccess
    {
    public:
        virtual ~ChainAccess() = default;

        virtual bool GetBlock(const uint256& block_hash, uint256& merkle_root_out, int& depth_out) const = 0;
    };

    struct SpentOutput
    {
        CScript scriptPubKey;
        CAmount value{0};
        CAsset asset;
        bool value_known{false};
    };

    bool HasKnowledgeAsymmetry(const CScript& spk);

    bool CheckAnchorBounds(const DropKickPayloadEntity& payload, std::string& err);

    bool CheckCoverage(const CTransaction& tx, const DropKickPayloadEntity& payload, const std::vector<SpentOutput>& spent, std::string& err);

    bool CheckPayout(const CTransaction& tx, const DropKickPayloadEntity& payload, unsigned int payload_index, std::string& err);

    bool CheckFee(const CTransaction& tx, const std::vector<SpentOutput>& spent, std::string& err);

    bool CheckOpening(const DropKickPayloadEntity& payload, const ChainAccess& chain, std::vector<CMutableTransaction>& anchor_txs_out, std::string& err);

    bool CheckBinding(const DropKickPayloadEntity& payload, const std::vector<CMutableTransaction>& anchor_txs, std::string& err);

    bool CheckClaims(const CTransaction& tx, const DropKickPayloadEntity& payload, const std::vector<SpentOutput>& spent, std::string& err);

    bool CheckPqSig(const CTransaction& tx, const DropKickPayloadEntity& payload, unsigned int payload_index, std::string& err);

    bool CheckDropKickTransaction(const CTransaction& tx, const std::vector<SpentOutput>& spent, const ChainAccess& chain, std::string& err);
}

#endif
