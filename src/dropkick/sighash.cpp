#include <dropkick/sighash.h>

namespace DropKickSighash
{
    bool BlankedPayloadScript(const DropKickPayloadEntity& payload, CScript& spk_out)
    {
        DropKickPayloadEntity payload_blanked = payload;
        payload_blanked.sig.clear();
        spk_out.clear();

        try
        {
            DataStream s;
            s << payload_blanked;
            spk_out << OP_RETURN << s;
        } catch(const std::exception&) {
            return false;
        }
        
        return true;
    }

    bool BuildSigningForm(const CTransaction& tx, unsigned int payload_index, const DropKickPayloadEntity& payload, CMutableTransaction& tx_out)
    {
        CScript blanked;
        if (!BlankedPayloadScript(payload, blanked)) return false;
        
        CMutableTransaction star{tx};
        if (payload_index >= star.vout.size()) return false;
        for (CTxIn& in : star.vin) in.scriptSig.clear();
        star.vout[payload_index].scriptPubKey = blanked;

        tx_out = star;
        return true;
    }

    bool ComputeSighash(const CTransaction& tx, unsigned int payload_index, const DropKickPayloadEntity& payload, uint256& sighash_out)
    {
        CMutableTransaction star;
        if (!BuildSigningForm(tx, payload_index, payload, star)) return false;

        try
        {
            DataStream s;
            s << TX_NO_WITNESS(CTransaction(star));
            HashWriter h{DropKickHashes::HASHER_DROPKICK_SIGHASH};
            h.write(MakeByteSpan(s));
            sighash_out = h.GetSHA256();
        } catch (const std::exception&) {
            return false;
        }

        return true;
    }
}