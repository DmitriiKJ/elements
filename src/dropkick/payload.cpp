#include <dropkick/payload.h>

#include <script/script.h>
#include <streams.h>

namespace DropKickPayload
{
    bool ParsePayloadScript(const CScript& spk, std::vector<unsigned char>& data_out)
    {
        if (spk.empty() || spk[0] != OP_RETURN) return false;

        CScript::const_iterator pc = spk.begin() + 1;
        opcodetype opcode;
        if (!spk.GetOp(pc, opcode, data_out)) return false;
        if (opcode > OP_PUSHDATA4) return false;
        if (pc != spk.end()) return false;

        return (CScript() << OP_RETURN << data_out) == spk;
    }

    bool HasPayloadOutput(const CTransaction& tx)
    {
        for (const CTxOut& out : tx.vout)
        {
            if (!out.scriptPubKey.empty() && out.scriptPubKey[0] == OP_RETURN) return true;
        }
        return false;
    }

    bool ExtractPayload(const CTransaction& tx, unsigned int& index_out, DropKickPayloadEntity& payload_out)
    {
        // Only 1 OP_RETURN is allowed in the reveal tx
        bool found = false;
        std::vector<unsigned char> data;

        for (unsigned int i = 0; i < tx.vout.size(); i++) 
        {
            const CTxOut& out = tx.vout[i];
            if (out.scriptPubKey.empty() || out.scriptPubKey[0] != OP_RETURN) continue;
            if (found) return false;

            if (!ParsePayloadScript(out.scriptPubKey, data)) return false;
            if (!out.nValue.IsExplicit() || out.nValue.GetAmount() != 0) return false;

            index_out = i;
            found = true;
        }
        if (!found) return false;

        try 
        {
            DataStream s{data};
            s >> payload_out;
            if (!s.empty()) return false;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }
}
