#ifndef BITCOIN_PRIMITIVES_DROPKICK_H
#define BITCOIN_PRIMITIVES_DROPKICK_H

#include <uint256.h>
#include <cstdint>
#include <vector>
#include <crypto/shrincs/shrincs.h>
#include <serialize.h>

namespace DropKickConstEnums
{
    static constexpr size_t PUBKEY_SIZE = 33;
    static constexpr size_t XPRV_SIZE = 78;

    static constexpr int COMMITMENT_DEPTH = 1440;
    static constexpr int64_t FEE_RATIO_NUM = 1;
    static constexpr int64_t FEE_RATIO_DEN = 1000;

    static constexpr size_t MAX_TX_DEPTH = 16;
    static constexpr size_t MAX_TX_LEN = 100000;

    enum DropKickWitType
    {
        PublicKey = 1,
        ExtendedPrivateKey = 2,
        Script = 3
    };

    enum DropKickOutType
    {
        P2PKH = 1,
        P2WPKH = 2,
        P2SH_P2WPKH = 3,
        P2SH = 4,
        P2WSH = 5
    };
}

template <size_t Size>
struct FixedBytesFormatter
{
    template <typename Stream>
    void Ser(Stream& s, const std::vector<unsigned char>& v)
    {
        if (v.size() != Size) throw std::ios_base::failure("fixed-size field has wrong length");
        s.write(MakeByteSpan(v));
    }
    template <typename Stream>
    void Unser(Stream& s, std::vector<unsigned char>& v)
    {
        v.resize(Size);
        s.read(AsWritableBytes(Span{v}));
    }
};

using PkField = FixedBytesFormatter<Parameters::N>;

template <size_t Count>
struct FixedHashesFormatter
{
    template <typename Stream>
    void Ser(Stream& s, const std::vector<uint256>& v)
    {
        if (v.size() != Count) throw std::ios_base::failure("fixed-size path has wrong length");
        for (const uint256& h : v) s << h;
    }
    template <typename Stream>
    void Unser(Stream& s, std::vector<uint256>& v)
    {
        v.resize(Count);
        for (uint256& h : v) s >> h;
    }
};

using AggPath = FixedHashesFormatter<14>;

class DropKickAnchor
{
public:
    uint256 blockHash;
    uint32_t txIndex;
    std::vector<uint256> txPath;
    std::vector<uint8_t> txData;

    bool CheckAnchorLimits() const;

    SERIALIZE_METHODS(DropKickAnchor, obj)
    {
        READWRITE(obj.blockHash, COMPACTSIZE(obj.txIndex), obj.txPath, obj.txData);
    }
};

typedef std::vector<uint8_t> DropKickSalvagerSPK;

class DropKickWitness
{
public:
    uint32_t anchorIndex;
    uint32_t svIndex;
    uint64_t svSat;
    uint16_t leafIndex;
    std::vector<uint256> aggPath;
    uint8_t witType;
    std::vector<uint8_t> witData;

    bool CheckWitness() const;

    SERIALIZE_METHODS(DropKickWitness, obj)
    {
        READWRITE(COMPACTSIZE(obj.anchorIndex), COMPACTSIZE(obj.svIndex), obj.svSat, obj.leafIndex, Using<AggPath>(obj.aggPath), obj.witType, obj.witData);
    }
};

class DropKickClaim
{
public:
    uint32_t inputIndex;
    uint32_t witIndex;
    uint8_t outType;
    std::vector<uint32_t> path;

    SERIALIZE_METHODS(DropKickClaim, obj)
    {
        READWRITE(COMPACTSIZE(obj.inputIndex), COMPACTSIZE(obj.witIndex), obj.outType, obj.path);
    }
};

class DropKickPayloadEntity
{
public:
    uint8_t version;
    SHRINCS::PublicKey pkPq;
    std::vector<DropKickAnchor> anchors;
    std::vector<DropKickSalvagerSPK> salvagers;
    std::vector<DropKickWitness> witnesses;
    std::vector<DropKickClaim> claims;
    std::vector<uint8_t> sig;

    SERIALIZE_METHODS(DropKickPayloadEntity, obj)
    {
        READWRITE(obj.version,
          Using<PkField>(obj.pkPq.seed),
          Using<PkField>(obj.pkPq.sl_root),
          Using<PkField>(obj.pkPq.sf_root),
          obj.anchors, obj.salvagers, obj.witnesses, obj.claims, obj.sig);
    }
};

#endif // BITCOIN_PRIMITIVES_DROPKICK_H