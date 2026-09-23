#include <dropkick/hashes.h>

namespace DropKickHashes
{
    const HashWriter HASHER_DROPKICK_COMMIT  = TaggedHash("DropKick/commit");
    const HashWriter HASHER_DROPKICK_INNER   = TaggedHash("DropKick/inner");
    const HashWriter HASHER_DROPKICK_LEAF    = TaggedHash("DropKick/leaf");
    const HashWriter HASHER_DROPKICK_BRANCH  = TaggedHash("DropKick/branch");
    const HashWriter HASHER_DROPKICK_SIGHASH = TaggedHash("DropKick/sighash");

    uint256 AggLeafHash(const uint256& commitment)
    {
        HashWriter h{HASHER_DROPKICK_LEAF};
        h << commitment;
        return h.GetSHA256();
    }

    uint256 AggBranchHash(const uint256& left, const uint256& right)
    {
        HashWriter h{HASHER_DROPKICK_BRANCH};
        h << left << right;
        return h.GetSHA256();
    }

    bool ComputeAggRoot(const uint256& leaf, const std::vector<uint256>& path, uint16_t leaf_index, uint256& root_out)
    {
        if (path.size() != AGG_TREE_HEIGHT) return false;
        if (leaf_index >= AGG_TREE_LEAVES) return false;

        root_out = leaf;
        for (uint8_t i = 0; i < AGG_TREE_HEIGHT; i++)
        {
            root_out = (((leaf_index >> i) & 1) == 0) ? AggBranchHash(root_out, path[i]) : AggBranchHash(path[i], root_out);
        }

        return true;
    }

    bool ComputeBlockMerkleRoot(const uint256& txid, const std::vector<uint256>& path, uint32_t tx_index, uint256& root_out)
    {
        if (path.size() >= 32) return false;
        if (tx_index >= (uint32_t{1} << path.size())) return false;

        root_out = txid;
        for (uint8_t i = 0; i < path.size(); i++)
        {
            HashWriter h;
            if (((tx_index >> i) & 1) == 0)
            {
                h << root_out << path[i];
                root_out = h.GetHash();
            }
            else
            {
                h << path[i] << root_out;
                root_out = h.GetHash();
            } 
        }

        return true;
    }

    uint256 TxDataHash(const std::vector<unsigned char>& tx_data)
    {
        return Hash(tx_data);
    }
}