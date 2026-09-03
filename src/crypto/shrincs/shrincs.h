#ifndef SHRINCS_H
#define SHRINCS_H

#include <random>
#include <vector>
#include <script/script.h>
#include "xmss.h"
#include "fxmss.h"
#include "fors.h"
#include "slh_dsa.h"

namespace SHRINCS {
    inline constexpr uint32_t PUBKEY_SIZE = 3 * N;
    inline constexpr uint32_t SECKEY_SIZE = 5 * N + 2;

    inline constexpr uint32_t SF_INDICATOR_SIZE = 1;
    inline constexpr uint32_t SF_LEAF_INDEX_SIZE_MIN = 1;
    inline constexpr uint32_t SF_LEAF_INDEX_SIZE_MAX = 8;
    inline constexpr uint32_t SF_WOTS_PART_SIZE = 2 + WOTS_C_CHAINS_SIZE;
    inline constexpr uint32_t SF_SIGNATURE_SIZE_MIN = SF_INDICATOR_SIZE + N + SF_LEAF_INDEX_SIZE_MIN + FXMSS_SIGNATURE_SIZE_MIN;
    inline constexpr uint32_t SF_SIGNATURE_SIZE_MAX = SF_INDICATOR_SIZE + N + SF_LEAF_INDEX_SIZE_MAX + FXMSS_SIGNATURE_SIZE_MAX;
    inline constexpr uint32_t SL_SIGNATURE_SIZE = SF_INDICATOR_SIZE + SPHX_SIGNATURE_SIZE;

    inline constexpr uint32_t sf_leaf_index_size(uint32_t leaf_depth)
    {
        return ((leaf_depth < 64 ? leaf_depth : 64) + 7) >> 3;
    }

    inline constexpr uint32_t SL_FORS_PART_COUNT = SPHX_FORS_COUNT;
    inline constexpr uint32_t SL_FORS_PART_SIZE = FORS_SIGNATURE_SIZE / SL_FORS_PART_COUNT;
    inline constexpr uint32_t SL_HT_PART_COUNT = SPHX_LAYER_COUNT << 1;
    inline constexpr uint32_t SL_HT_PART_SIZE = HYPERTREE_SIGNATURE_SIZE / SL_HT_PART_COUNT;
    inline constexpr uint32_t SL_PART_COUNT = 1 + SL_FORS_PART_COUNT + SL_HT_PART_COUNT;
    inline constexpr uint32_t SF_PART_COUNT_BASE = 3;

    inline constexpr int64_t Q_EMPTY = 0;
    inline constexpr int64_t Q_STATELESS = FXMSS_HEIGHT + 1;

    static_assert(SL_FORS_PART_SIZE <= MAX_SCRIPT_ELEMENT_SIZE);
    static_assert(SL_HT_PART_SIZE <= MAX_SCRIPT_ELEMENT_SIZE);
    static_assert(SF_WOTS_PART_SIZE <= MAX_SCRIPT_ELEMENT_SIZE);
    static_assert(SL_FORS_PART_SIZE * SL_FORS_PART_COUNT == FORS_SIGNATURE_SIZE);
    static_assert(SL_HT_PART_SIZE * SL_HT_PART_COUNT == HYPERTREE_SIGNATURE_SIZE);

    class PublicKey
    {
        public:
            std::vector<unsigned char> seed;
            std::vector<unsigned char> sl_root;
            std::vector<unsigned char> sf_root;

            PublicKey();
    };

    class SecretKey
    {
        public:
            std::vector<unsigned char> seed;
            std::vector<unsigned char> prf;
            std::vector<unsigned char> structure;
            PublicKey pk;

            SecretKey();
    };

    void generate_random_bytes(unsigned char* buffer, size_t length);

    bool shrincs_keygen(const std::vector<unsigned char>& seed, const std::vector<unsigned char>& structure, SecretKey& out_sk);
    bool shrincs_sf_leaf_select(const std::vector<unsigned char>& structure, const uint64_t* state_ctr, uint64_t* out_lr, uint8_t* out_bt);
    bool shrincs_sign(const std::vector<unsigned char>& message, const std::vector<unsigned char>& ctx, const SecretKey& sk, const uint64_t* state_ctr, const std::vector<unsigned char>& opt_rand, std::vector<unsigned char>& out);
    bool shrincs_verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature, const std::vector<unsigned char>& ctx, const PublicKey& pk);

    bool shrincs_pubkey_serialize(const PublicKey& pk, std::vector<unsigned char>& out);
    bool shrincs_pubkey_parse(const std::vector<unsigned char>& bytes, PublicKey& out_pk);
    bool shrincs_seckey_serialize(const SecretKey& sk, std::vector<unsigned char>& out);
    bool shrincs_seckey_parse(const std::vector<unsigned char>& bytes, SecretKey& out_sk);

    void shrincs_sig_to_witness(CScriptWitness& witness, const std::vector<unsigned char>& sig, bool sighash_type_ext);
}

#endif
