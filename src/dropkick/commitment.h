#ifndef BITCOIN_DROPKICK_COMMITMENT_H
#define BITCOIN_DROPKICK_COMMITMENT_H

#include <dropkick/hashes.h>

namespace DropKickCommitment
{
    bool Commit(const std::vector<unsigned char>& witness, const SHRINCS::PublicKey& pk_pq, const DropKickSalvagerSPK& spk, uint64_t sv_sat, uint256& out);
}

#endif