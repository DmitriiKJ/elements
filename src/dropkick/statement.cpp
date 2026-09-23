#include <dropkick/statement.h>
using namespace DropKickConstEnums;

namespace DropKickStatement
{
    bool IsAdmissiblePair(uint8_t wit_type, uint8_t out_type)
    {
        return
        (
            (
                (wit_type == DropKickWitType::PublicKey || wit_type == DropKickWitType::ExtendedPrivateKey) &&
                (out_type == DropKickOutType::P2PKH ||
                out_type == DropKickOutType::P2WPKH ||
                out_type == DropKickOutType::P2SH_P2WPKH)
            ) 
            ||
            (
                (wit_type == DropKickWitType::Script) &&
                (out_type == DropKickOutType::P2SH ||
                out_type == DropKickOutType::P2WSH)
            )
        );
    }

    bool ExtractStatement(const CScript& spk, uint8_t out_type, std::vector<unsigned char>& statement_out)
    {
        if (!(
            (out_type == DropKickOutType::P2PKH && spk.IsPayToPubkeyHash()) ||
            (out_type == DropKickOutType::P2WPKH && spk.IsPayToWitnessPubkeyHash()) ||
            (out_type == DropKickOutType::P2SH_P2WPKH && spk.IsPayToScriptHash()) ||
            (out_type == DropKickOutType::P2SH && spk.IsPayToScriptHash()) ||
            (out_type == DropKickOutType::P2WSH && spk.IsPayToWitnessScriptHash())
        )) return false;

        statement_out.clear();
        switch (out_type)
        {
        case DropKickOutType::P2PKH:
            statement_out.insert(statement_out.end(), spk.begin() + 3, spk.begin() + 23);
            break;
        case DropKickOutType::P2WPKH:
        case DropKickOutType::P2SH_P2WPKH:
        case DropKickOutType::P2SH:
            statement_out.insert(statement_out.end(), spk.begin() + 2, spk.begin() + 22);
            break;
        case DropKickOutType::P2WSH:
            statement_out.insert(statement_out.end(), spk.begin() + 2, spk.begin() + 34);
            break;
        default: return false;
        }

        return true;
    }

    bool ResolveWitness(uint8_t wit_type, const std::vector<unsigned char>& wit_data, const std::vector<uint32_t>& path, std::vector<unsigned char>& witness_out)
    {
        if (wit_type != DropKickWitType::ExtendedPrivateKey && !path.empty()) return false;

        if (wit_type == DropKickWitType::PublicKey)
        {
            witness_out.assign(wit_data.begin(), wit_data.end());
        }
        else if (wit_type == DropKickWitType::ExtendedPrivateKey)
        {
            if (wit_data.size() != BIP32_EXTKEY_WITH_VERSION_SIZE) return false;
            CExtKey xkey;
            xkey.Decode(wit_data.data() + 4); // skip version
            if (!xkey.key.IsValid()) return false;

            for (uint32_t step : path)
            {
                CExtKey next;
                if (!xkey.Derive(next, step)) return false;
                xkey = next;
            }

            const CPubKey pk = xkey.key.GetPubKey();
            witness_out.assign(pk.begin(), pk.end());
        }
        else if (wit_type == DropKickWitType::Script)
        {
            try 
            {
                DataStream s{wit_data};
                s >> witness_out;
                if (!s.empty()) return false;
            } catch (const std::exception&) {
                return false;
            }
        }
        else return false;

        return true;
    }

    bool ComputeStatement(const std::vector<unsigned char>& witness, uint8_t out_type, std::vector<unsigned char>& statement_out)
    {
        statement_out.clear();
        switch (out_type)
        {
        case DropKickOutType::P2PKH:
        case DropKickOutType::P2WPKH:
        {
            if (witness.size() != PUBKEY_SIZE) return false;
            uint160 res = Hash160(witness);
            statement_out.assign(res.begin(), res.end());
            break;
        }
        case DropKickOutType::P2SH_P2WPKH:
        {
            if (witness.size() != PUBKEY_SIZE) return false;
            const uint160 kh = Hash160(witness);
            const CScript rs = CScript() << OP_0 << std::vector<unsigned char>(kh.begin(), kh.end());
            const uint160 h = Hash160(rs);
            statement_out.assign(h.begin(), h.end());
            break;
        }
        case DropKickOutType::P2SH:
        {
            uint160 res = Hash160(witness);
            statement_out.assign(res.begin(), res.end());
            break;
        }
        case DropKickOutType::P2WSH:
        {
            uint256 h;
            CSHA256().Write(witness.data(), witness.size()).Finalize(h.begin());
            statement_out.assign(h.begin(), h.end());
            break;
        }
        default: return false;
        }

        return true;
    }

    bool CheckStatement(const CScript& spk, uint8_t wit_type, const std::vector<unsigned char>& wit_data, uint8_t out_type, const std::vector<uint32_t>& path)
    {
        if (!IsAdmissiblePair(wit_type, out_type)) return false;

        std::vector<unsigned char> expected_statement;
        if (!ExtractStatement(spk, out_type, expected_statement)) return false;

        std::vector<unsigned char> witness;
        if (!ResolveWitness(wit_type, wit_data, path, witness)) return false;

        std::vector<unsigned char> statement;
        if (!ComputeStatement(witness, out_type, statement)) return false;

        return expected_statement == statement;
    }
}