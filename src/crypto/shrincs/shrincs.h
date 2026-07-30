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

    inline constexpr uint32_t SF_LEAF_INDEX_SIZE = 8;
    inline constexpr uint32_t SF_WOTS_PART_SIZE = 2 + WOTS_C_CHAINS_SIZE;
    inline constexpr uint32_t SF_SIGNATURE_SIZE_MIN = N + SF_LEAF_INDEX_SIZE + FXMSS_SIGNATURE_SIZE_MIN;
    inline constexpr uint32_t SF_SIGNATURE_SIZE_MAX = N + SF_LEAF_INDEX_SIZE + FXMSS_SIGNATURE_SIZE_MAX;

    inline constexpr uint32_t SL_FORS_PART_COUNT = SPHX_FORS_COUNT;
    inline constexpr uint32_t SL_FORS_PART_SIZE = FORS_SIGNATURE_SIZE / SL_FORS_PART_COUNT;
    inline constexpr uint32_t SL_HT_PART_COUNT = SPHX_LAYER_COUNT << 1;
    inline constexpr uint32_t SL_HT_PART_SIZE = HYPERTREE_SIGNATURE_SIZE / SL_HT_PART_COUNT;
    inline constexpr uint32_t SL_PART_COUNT = 1 + SL_FORS_PART_COUNT + SL_HT_PART_COUNT;

    // q distinguishes the two paths on the stack. A stateful q counts the Merkle
    // path elements, which reaches FXMSS_HEIGHT, so the stateless marker sits above it.
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

    bool shrincs_keygen(unsigned char* bytes, const std::vector<unsigned char>& structure, SecretKey& out_sk);
    bool shrincs_sf_leaf_select(const std::vector<unsigned char>& structure, uint32_t state_ctr, uint64_t* out_lr, uint8_t* out_bt);
    bool shrincs_sign(const std::vector<unsigned char>& message, const SecretKey& sk, uint32_t state_ctr, const std::vector<unsigned char>& opt_rand, std::vector<unsigned char>& out);
    bool shrincs_verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature, const PublicKey& pk);

    bool shrincs_pubkey_serialize(const PublicKey& pk, std::vector<unsigned char>& out);
    bool shrincs_pubkey_parse(const std::vector<unsigned char>& bytes, PublicKey& out_pk);
    bool shrincs_seckey_serialize(const SecretKey& sk, std::vector<unsigned char>& out);
    bool shrincs_seckey_parse(const std::vector<unsigned char>& bytes, SecretKey& out_sk);

    void shrincs_sig_to_witness(CScriptWitness& witness, const std::vector<unsigned char>& sig, bool sighash_type_ext);
}

#endif
