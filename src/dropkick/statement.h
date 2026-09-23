#ifndef BITCOIN_DROPKICK_STATEMENT_H
#define BITCOIN_DROPKICK_STATEMENT_H

#include <script/script.h>
#include <cstdint>
#include <vector>
#include <primitives/dropkick.h>
#include <key.h>
#include <hash.h>
#include <streams.h>

namespace DropKickStatement
{
    bool IsAdmissiblePair(uint8_t wit_type, uint8_t out_type);

    bool ExtractStatement(const CScript& spk, uint8_t out_type, std::vector<unsigned char>& statement_out);

    bool ResolveWitness(uint8_t wit_type, const std::vector<unsigned char>& wit_data, const std::vector<uint32_t>& path, std::vector<unsigned char>& witness_out);

    bool ComputeStatement(const std::vector<unsigned char>& witness, uint8_t out_type, std::vector<unsigned char>& statement_out);

    bool CheckStatement(const CScript& spk, uint8_t wit_type, const std::vector<unsigned char>& wit_data, uint8_t out_type, const std::vector<uint32_t>& path);
}

#endif
