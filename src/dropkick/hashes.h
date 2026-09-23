#ifndef BITCOIN_DROPKICK_HASHES_H
#define BITCOIN_DROPKICK_HASHES_H

#include <hash.h>
#include <uint256.h>
#include <cstdint>
#include <vector>
#include <primitives/dropkick.h>
#include <streams.h>

namespace DropKickHashes {
    static constexpr uint32_t AGG_TREE_HEIGHT = 14;
    static constexpr uint32_t AGG_TREE_LEAVES = 1u << AGG_TREE_HEIGHT;

    extern const HashWriter HASHER_DROPKICK_COMMIT;
    extern const HashWriter HASHER_DROPKICK_INNER;
    extern const HashWriter HASHER_DROPKICK_LEAF;
    extern const HashWriter HASHER_DROPKICK_BRANCH;
    extern const HashWriter HASHER_DROPKICK_SIGHASH;

    uint256 AggLeafHash(const uint256& commitment);

    uint256 AggBranchHash(const uint256& left, const uint256& right);

    bool ComputeAggRoot(const uint256& leaf, const std::vector<uint256>& path, uint16_t leaf_index, uint256& root_out);

    bool ComputeBlockMerkleRoot(const uint256& txid, const std::vector<uint256>& path, uint32_t tx_index, uint256& root_out);

    uint256 TxDataHash(const std::vector<unsigned char>& tx_data);
}

#endif // BITCOIN_DROPKICK_HASHES_H
