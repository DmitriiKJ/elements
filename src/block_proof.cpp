// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <chain.h>
#include <primitives/block.h>
#include <script/interpreter.h>
#include <script/generic.hpp>
#include <crypto/shrincs/shrincs.h>

bool CheckChallenge(const CBlockHeader& block, const CBlockIndex& indexLast, const Consensus::Params& params)
{
    if (g_signed_blocks) {
        return block.proof.challenge == indexLast.get_proof().challenge;
    } else {
        return block.nBits == GetNextWorkRequired(&indexLast, &block, params);
    }
}

static bool CheckProofGeneric(const CBlockHeader& block, const uint32_t max_block_signature_size, const CScript& challenge, const CScript& scriptSig, const CScriptWitness& witness)
{
    // Legacy blocks have empty witness, dynafed blocks have empty scriptSig
    bool is_dyna = !witness.stack.empty();

    // Check signature limits for blocks
    if (scriptSig.size() > max_block_signature_size) {
        assert(!is_dyna);
        return false;
    } else if (witness.GetSerializedSize() > max_block_signature_size) {
        assert(is_dyna);
        return false;
    }

    // Some anti-DoS flags, though max_block_signature_size caps the possible
    // danger in malleation of the block witness data.
    unsigned int proof_flags = SCRIPT_VERIFY_P2SH // For cleanstack evaluation under segwit flag
        | SCRIPT_VERIFY_STRICTENC // Minimally-sized DER sigs
        | SCRIPT_VERIFY_NULLDUMMY // No extra data stuffed into OP_CMS witness
        | SCRIPT_VERIFY_CLEANSTACK // No extra pushes leftover in witness
        | SCRIPT_VERIFY_MINIMALDATA // Pushes are minimally-sized
        | SCRIPT_VERIFY_SIGPUSHONLY // Witness is push-only
        | SCRIPT_VERIFY_LOW_S // Stop easiest signature fiddling
        | SCRIPT_VERIFY_WITNESS // Witness and to enforce cleanstack
        | (is_dyna ? SCRIPT_VERIFY_NONE : SCRIPT_NO_SIGHASH_BYTE); // Non-dynafed blocks do not have sighash byte
    return GenericVerifyScript(scriptSig, witness, challenge, proof_flags, block);
}

bool CheckProof(const CBlockHeader& block, const Consensus::Params& params)
{
    if (g_signed_blocks) {
        unsigned char keys_amount = 0;
        std::vector<unsigned char> pq_sig;
        const DynaFedParams& dynafed_params = block.m_dynafed_params;
        CScript fed_keys;
        CScript actual_script;

        bool is_dynafed = !block.m_dynafed_params.IsNull();

        if (is_dynafed) {
            fed_keys = block.m_dynafed_params.m_current.m_signblockscript;
            
            if (block.m_signblock_witness.stack.empty()) {
                return false;
            }
            
            std::vector<unsigned char> witness_script = block.m_signblock_witness.stack.back();
            actual_script = CScript(witness_script.begin(), witness_script.end());
        } else {
            fed_keys = params.signblockscript;
            actual_script = fed_keys; 
        }

        if (fed_keys.empty()) return false;
        
        bool is_shrincs = false;
        keys_amount = actual_script.back();
        size_t expected_shrincs_size = 1 + (keys_amount * 2 * N) + 1;
        if (actual_script.size() == expected_shrincs_size) {
            is_shrincs = true;
        }

        if (!is_shrincs) {
            if (is_dynafed) {
                return CheckProofGeneric(block, block.m_dynafed_params.m_current.m_signblock_witness_limit, fed_keys, CScript(), block.m_signblock_witness);
            } else {
                return CheckProofGeneric(block, params.max_block_signature_size, fed_keys, block.proof.solution, CScriptWitness());
            }
        } else {
            if (!block.m_signblock_witness.stack.empty()) {
                pq_sig = block.m_signblock_witness.stack[0];
            }
        }

        if (pq_sig.empty() || (actual_script[0] > keys_amount)) {
            return false;
        }

        uint256 hash_result;
        CSHA256().Write(actual_script.data(), actual_script.size()).Finalize(hash_result.begin());

        if (memcmp(hash_result.begin(), &fed_keys[2], 32) != 0) return false;

        uint256 hashToSign = block.GetHash();

        SHRINCS::PublicKey pk = SHRINCS::PublicKey();

        bool isValid = true;
        int signature_pased = 0;

        for (int i = 0; i < keys_amount; i++)
        {
            CScriptBase::iterator key_start = actual_script.begin() + 1 + 2 * N * i;
            pk.seed.assign(key_start, key_start + N);
            pk.root.assign(key_start + N, key_start + 2 * N);

            if (SHRINCS::shrincs_verify(hashToSign.begin(), pq_sig.data() + signature_pased * SL_SIZE, SL_SIZE, pk))
            {
                signature_pased += 1;
                if (signature_pased == actual_script[0])
                {
                    return true;
                }
            }
        }

        return false;

    } else {
        return CheckProofOfWork(block.GetHash(), block.nBits, params);
    }
}

bool CheckProofSignedParent(const CBlockHeader& block, const Consensus::Params& params)
{
    const DynaFedParams& dynafed_params = block.m_dynafed_params;
    if (dynafed_params.IsNull()) {
        return CheckProofGeneric(block, params.max_block_signature_size, params.parent_chain_signblockscript, block.proof.solution, CScriptWitness());
    } else {
        // Dynamic federations means we cannot validate the signer set
        // at least without tracking the parent chain more directly.
        // Note that we do not even serialize dynamic federation block witness data
        // currently for merkle proofs which is the only context in which
        // this function is currently used.
        return true;
    }
}
