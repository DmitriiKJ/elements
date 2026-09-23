#include <dropkick/publication.h>

namespace DropKickPublication 
{
    bool ParsePublication(const CScript& spk, uint256& root_out)
    {
        if (!(spk.size() == SCRIPT_SIZE && spk[0] == OP_RETURN && spk[1] == PUSH_SIZE)) return false;

        if (!std::equal(std::begin(MAGIC), std::end(MAGIC), spk.data() + 2)) return false;

        root_out = uint256(Span<const unsigned char>(spk.data() + 6, 32));
        
        return true;
    }

    std::vector<uint256> ExtractRoots(const CTransaction& tx)
    {
        std::vector<uint256> roots;
        uint256 tmp;
        for (const CTxOut& out : tx.vout)
        {
            if (ParsePublication(out.scriptPubKey, tmp))
            {
                roots.push_back(tmp);
            }
        }

        return roots;
    }

    bool PublishesRoot(const CTransaction& tx, const uint256& root)
    {
        std::vector<uint256> roots = ExtractRoots(tx);
        return std::find(roots.begin(), roots.end(), root) != roots.end();
    }

    bool DecodeAnchorTx(const std::vector<unsigned char>& tx_data, CMutableTransaction& tx_out)
    {
        try {
            DataStream s{tx_data};
            s >> TX_NO_WITNESS(tx_out);
            if (!s.empty()) return false;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    CScript MakePublicationScript(const uint256& root)
    {
        std::vector<unsigned char> data;
        data.reserve(PUSH_SIZE);
        data.insert(data.end(), std::begin(MAGIC), std::end(MAGIC));
        data.insert(data.end(), root.begin(), root.end());

        return CScript() << OP_RETURN << data;
    }
}