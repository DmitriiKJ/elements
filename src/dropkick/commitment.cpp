#include <dropkick/commitment.h>

namespace DropKickCommitment
{
    static bool OpeningMessage(const SHRINCS::PublicKey& pk_pq, const DropKickSalvagerSPK& spk, uint64_t sv_sat, std::vector<unsigned char>& out)
    {
        std::vector<unsigned char> pk_bytes;
        if (!SHRINCS::shrincs_pubkey_serialize(pk_pq, pk_bytes)) return false;

        DataStream s;
        s.write(MakeByteSpan(pk_bytes));
        s << spk;
        s << sv_sat;
        out.assign(UCharCast(s.data()), UCharCast(s.data()) + s.size());
        return true;
    }

    bool Commit(const std::vector<unsigned char>& witness, const SHRINCS::PublicKey& pk_pq, const DropKickSalvagerSPK& spk, uint64_t sv_sat, uint256& out)
    {
        std::vector<unsigned char> cmsg;
        if (!OpeningMessage(pk_pq, spk, sv_sat, cmsg)) return false;

        HashWriter inner{DropKickHashes::HASHER_DROPKICK_INNER};
        inner.write(MakeByteSpan(witness));
        inner.write(MakeByteSpan(cmsg));
        const uint256 inner_hash = inner.GetSHA256();

        HashWriter outer{DropKickHashes::HASHER_DROPKICK_COMMIT};
        outer << inner_hash;
        outer.write(MakeByteSpan(cmsg));
        out = outer.GetSHA256();
        return true;
    }
}