#include <primitives/dropkick.h>

using namespace DropKickConstEnums;

bool IsDropKickPubKey(const std::vector<uint8_t>& v)
{
    return (v.size() == PUBKEY_SIZE && (v[0] == 0x02 || v[0] == 0x03)) ||
        (v.size() == UNCOMPRESSED_PUBKEY_SIZE && v[0] == 0x04);
}

bool DropKickAnchor::CheckAnchorLimits() const
{
    return txPath.size() <= MAX_TX_DEPTH && txData.size() <= MAX_TX_LEN;
}

bool DropKickWitness::CheckWitness() const
{
    return aggPath.size() == 14 && (
        (witType == DropKickWitType::PublicKey && IsDropKickPubKey(witData)) ||
        (witType == DropKickWitType::ExtendedPrivateKey && witData.size() == XPRV_SIZE) || 
        (witType == DropKickWitType::Script)
    );
}