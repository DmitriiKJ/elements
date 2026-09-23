#include <primitives/dropkick.h>

using namespace DropKickConstEnums;

bool DropKickAnchor::CheckAnchorLimits() const
{
    return txPath.size() <= MAX_TX_DEPTH && txData.size() <= MAX_TX_LEN;
}

bool DropKickWitness::CheckWitness() const
{
    return aggPath.size() == 14 && (
        (witType == DropKickWitType::PublicKey && witData.size() == PUBKEY_SIZE) || 
        (witType == DropKickWitType::ExtendedPrivateKey && witData.size() == XPRV_SIZE) || 
        (witType == DropKickWitType::Script)
    );
}