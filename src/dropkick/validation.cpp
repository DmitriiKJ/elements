#include <dropkick/validation.h>

#include <chainparams.h>

namespace DropKickValidation
{
    bool HasKnowledgeAsymmetry(const CScript& spk)
    {
        return spk.IsPayToPubkeyHash()
        || spk.IsPayToWitnessPubkeyHash()
        || spk.IsPayToScriptHash() // Both P2SH and P2SH-P2WPKH
        || spk.IsPayToWitnessScriptHash();
    }

    bool CheckAnchorBounds(const DropKickPayloadEntity& payload, std::string& err)
    {
        for (const DropKickAnchor& anchor : payload.anchors)
        {
            if (!anchor.CheckAnchorLimits())
            {
                err = "Anchor exceeds its length bounds (tx_depth > 16 or tx_len > 100000).";
                return false;
            }
        }

        return true;
    }

    bool CheckCoverage(const CTransaction& tx, const DropKickPayloadEntity& payload, const std::vector<SpentOutput>& spent, std::string& err)
    {
        if (spent.size() != tx.vin.size())
        {
            err = "Spent output set does not match the input count.";
            return false;
        }

        for (const DropKickWitness& w : payload.witnesses)
        {
            if (w.anchorIndex >= payload.anchors.size()) 
            { 
                err = "Witness record names an anchor outside the payload.";
                return false;
            }

            if (!w.CheckWitness()) 
            { 
                err = "Witness record is malformed for its type."; return false; 
            }
        }

        std::vector<bool> claimed(tx.vin.size(), false);

        for (const DropKickClaim& claim : payload.claims)
        {
            if (claim.inputIndex >= tx.vin.size())
            {
                err = "Claim names an input outside the transaction.";
                return false;
            }
            if (claimed[claim.inputIndex])
            {
                err = "Claim names an input that another claim already names.";
                return false;
            }
            claimed[claim.inputIndex] = true;
            if (claim.witIndex >= payload.witnesses.size())
            {
                err = "Claim names a witness record outside the payload.";
                return false;
            }
        }

        for (uint32_t i = 0; i < tx.vin.size(); i++)
        {
            if (tx.vin[i].m_is_pegin) continue;
            if (!HasKnowledgeAsymmetry(spent[i].scriptPubKey)) continue;
            if (!claimed[i])
            {
                err = "Input spends a hash-protected output but no claim names it.";
                return false;
            }
        }

        return true;
    }

    bool CheckPayout(const CTransaction& tx, const DropKickPayloadEntity& payload, unsigned int payload_index, std::string& err)
    {
        const size_t M = payload.salvagers.size();
        std::vector<CAmount> totals(M, 0);
        std::vector<bool> named(M, false);

        for (const DropKickWitness& w : payload.witnesses) 
        {
            if (w.svIndex == 0)
            {
                if (w.svSat != 0)
                {
                    err = "Self-salvaged witness record carries a non-zero salvage fee.";
                    return false;
                }
                continue;
            }

            const size_t k = w.svIndex - 1;
            if (k >= M)
            {
                err = "Witness record names a salvager entry outside the payload.";
                return false;
            }

            named[k] = true;

            if (w.svSat > MAX_MONEY || totals[k] > MAX_MONEY - (CAmount)w.svSat)
            {
                err = "Salvage fees owed to one entry exceed the money supply.";
                return false;
            }
            totals[k] += w.svSat;
        }

        for (size_t k = 0; k < M; k++)
        {
            if (!named[k])
            {
                err = "Salvager entry is named by no witness record.";
                return false;
            }
        }

        uint32_t curr_out_idx = 0;
        for (uint32_t i = 0; i < M; i++)
        {
            if (totals[i] == 0) continue;
            if (curr_out_idx >= tx.vout.size())
            {
                err = "Transaction has fewer outputs than the salvage payouts it owes.";
                return false;
            }

            const CTxOut& out = tx.vout[curr_out_idx];

            if (out.scriptPubKey != CScript(payload.salvagers[i].begin(), payload.salvagers[i].end()))
            {
                err = "Salvage payout does not pay the script pubkey the payload names.";
                return false;
            }

            if (!out.nValue.IsExplicit() || out.nValue.GetAmount() < totals[i])
            {
                err = "Salvage payout is blinded or pays less than the fee owed.";
                return false;
            }

            if (!out.nAsset.IsExplicit() || out.nAsset.GetAsset() != Params().GetConsensus().pegged_asset)
            {
                err = "Salvage payout is not in the pegged asset.";
                return false;
            }

            curr_out_idx++;
        }

        if (payload_index != curr_out_idx)
        {
            err = "Payload output does not sit immediately after the salvage payouts.";
            return false;
        }

        return true;
    }

    bool CheckFee(const CTransaction& tx, const std::vector<SpentOutput>& spent, std::string& err)
    {
        if (tx.vin.size() != spent.size())
        {
            err = "Spent output set does not match the input count.";
            return false;
        }

        CAmount V = 0;
        for (uint32_t i = 0; i < tx.vin.size(); i++)
        {
            if (tx.vin[i].m_is_pegin) continue;
            if (!HasKnowledgeAsymmetry(spent[i].scriptPubKey)) continue;
            if (!spent[i].value_known)
            {
                err = "Reveal must know exact spending value.";
                return false;
            }
            if (spent[i].asset != Params().GetConsensus().pegged_asset) continue;
            V += spent[i].value;
        }

        const CAsset& pegged = Params().GetConsensus().pegged_asset;
        const CAmount fee = GetFeeMap(tx)[pegged];
        const int64_t required = (V * DropKickConstEnums::FEE_RATIO_NUM + DropKickConstEnums::FEE_RATIO_DEN - 1) / DropKickConstEnums::FEE_RATIO_DEN;

        if (fee < required) 
        { 
            err = "Fee doesn't satisfy ceil(V * γ_n / γ_d) limit."; 
            return false; 
        }

        return true;
    }

    bool CheckOpening(const DropKickPayloadEntity& payload, const ChainAccess& chain, std::vector<CMutableTransaction>& anchor_txs_out, std::string& err)
    {
        anchor_txs_out.clear();
        anchor_txs_out.reserve(payload.anchors.size());

        uint256 expected_merkle_root;
        int depth;
        for (const DropKickAnchor& anchor : payload.anchors)
        {
            if (!chain.GetBlock(anchor.blockHash, expected_merkle_root, depth))
            {
                err = "Anchor names a block that is unknown or not on the active chain.";
                return false;
            }

            if (depth < DropKickConstEnums::COMMITMENT_DEPTH)
            {
                err = "Commitment is not buried deep enough to be opened.";
                return false;
            }

            uint256 tx_hashed = DropKickHashes::TxDataHash(anchor.txData), merkle_root;

            if (!DropKickHashes::ComputeBlockMerkleRoot(tx_hashed, anchor.txPath, anchor.txIndex, merkle_root) || expected_merkle_root != merkle_root)
            {
                err = "Anchor merkle path does not lead to the block's transaction root.";
                return false;
            }

            CMutableTransaction anchor_tx;
            if (!DropKickPublication::DecodeAnchorTx(anchor.txData, anchor_tx)) 
            {
                err = "Tx data can't be decoded correctly.";
                return false;
            }

            if (DropKickPublication::ExtractRoots(CTransaction(anchor_tx)).empty()) 
            {
                err = "Anchor tx doesn't have any DropKick commits";
                return false;
            }

            anchor_txs_out.push_back(anchor_tx);
        }

        return true;
    }

    bool CheckBinding(const DropKickPayloadEntity& payload, const std::vector<CMutableTransaction>& anchor_txs, std::string& err)
    {
        uint256 commit, root;
        for (const DropKickWitness& witness : payload.witnesses)
        {
            if (witness.anchorIndex >= payload.anchors.size())
            {
                err = "Witness record names an anchor outside the payload.";
                return false;
            }

            if (witness.svIndex > payload.salvagers.size())
            {
                err = "Witness record names a salvager entry outside the payload.";
                return false;
            }

            static const DropKickSalvagerSPK EMPTY_SPK;
            const DropKickSalvagerSPK& spk = (witness.svIndex == 0)
                ? EMPTY_SPK
                : payload.salvagers[witness.svIndex - 1];

            if (!DropKickCommitment::Commit(witness.witData, payload.pkPq, spk, witness.svSat, commit))
            {
                err = "PQ pk can't be parsed.";
                return false;
            }

            if (!DropKickHashes::ComputeAggRoot(commit, witness.aggPath, witness.leafIndex, root))
            {
                err = "Aggregation path or commit leaf index is too long";
                return false;
            }

            if (!DropKickPublication::PublishesRoot(CTransaction(anchor_txs[witness.anchorIndex]), root))
            {
                err = "Commiting tx doesn't have witness commit";
                return false;
            }
        }

        return true;
    }

    bool CheckClaims(const CTransaction& tx, const DropKickPayloadEntity& payload, const std::vector<SpentOutput>& spent, std::string& err)
    {
        if (spent.size() != tx.vin.size())
        {
            err = "Spent output set does not match the input count.";
            return false;
        }

        for (const DropKickClaim& claim : payload.claims)
        {
            if (claim.inputIndex >= spent.size() || claim.witIndex >= payload.witnesses.size())
            {
                err = "Claim names an input or witness record outside the transaction.";
                return false;
            }

            const DropKickWitness& w = payload.witnesses[claim.witIndex];

            if (!DropKickStatement::CheckStatement(spent[claim.inputIndex].scriptPubKey, w.witType, w.witData, claim.outType, claim.path))
            {
                err = "Claim does not reproduce the statement embedded in the input's script pubkey.";
                return false;
            }
        }

        return true;
    }

    bool CheckPqSig(const CTransaction& tx, const DropKickPayloadEntity& payload, unsigned int payload_index, std::string& err)
    {
        uint256 sighash;
        if (!DropKickSighash::ComputeSighash(tx, payload_index, payload, sighash))
        {
            err = "Tx can't be serialized.";
            return false;
        }

        if (!SHRINCS::shrincs_verify(std::vector<unsigned char>(sighash.begin(), sighash.end()), payload.sig, {}, payload.pkPq))
        {
            err = "SHRINCS signature does not verify under the payload public key.";
            return false;
        }

        return true;
    }

    bool CheckDropKickTransaction(const CTransaction& tx, const std::vector<SpentOutput>& spent, const ChainAccess& chain, std::string& err)
    {
        DropKickPayloadEntity payload;
        uint32_t payload_index;
        if (!DropKickPayload::ExtractPayload(tx, payload_index, payload))
        {
            err = "Transaction carries no well-formed DropKick payload.";
            return false;
        }

        if (payload.version != 1)
        {
            err = "Unknown DropKick payload version.";
            return false;
        }

        if (!CheckAnchorBounds(payload, err)) return false;

        if (!CheckCoverage(tx, payload, spent, err)) return false;

        if (!CheckPayout(tx, payload, payload_index, err)) return false;
        if (!CheckFee(tx, spent, err)) return false;

        std::vector<CMutableTransaction> anchors_txs;
        if (!CheckOpening(payload, chain, anchors_txs, err)) return false;

        if (!CheckBinding(payload, anchors_txs, err)) return false;
        if (!CheckClaims(tx, payload, spent, err)) return false;

        if (!CheckPqSig(tx, payload, payload_index, err)) return false;

        return true;
    }
}