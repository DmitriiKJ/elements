#ifndef BITCOIN_CRYPTO_SHRINCS_SHRINCS_H
#define BITCOIN_CRYPTO_SHRINCS_SHRINCS_H

#include <random>
#include <vector>
#include <script/script.h>
#include <crypto/shrincs/xmss.h>
#include <crypto/shrincs/fxmss.h>
#include <crypto/shrincs/fors.h>
#include <crypto/shrincs/slh_dsa.h>

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

    // The signature is cut into parts of this size, the last one carrying the remainder.
    // 80 is MAX_STANDARD_P2WSH_STACK_ITEM_SIZE and MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE,
    // the relay policy cap, which is stricter than MAX_SCRIPT_ELEMENT_SIZE.
    inline constexpr uint32_t SIG_PART_SIZE = 80;

    // Length of a signature as serialized, less its leading indicator byte.
    inline constexpr uint32_t sf_body_size(uint32_t leaf_depth)
    {
        return N + sf_leaf_index_size(leaf_depth) + SF_WOTS_PART_SIZE + N * leaf_depth;
    }

    inline constexpr uint32_t SL_BODY_SIZE = SPHX_SIGNATURE_SIZE;

    inline constexpr uint32_t sig_part_count(uint32_t body_size)
    {
        return (body_size + SIG_PART_SIZE - 1) / SIG_PART_SIZE;
    }

    inline constexpr uint32_t SL_PART_COUNT = sig_part_count(SL_BODY_SIZE);

    inline constexpr int64_t Q_EMPTY = 0;
    inline constexpr int64_t Q_STATELESS = FXMSS_HEIGHT + 1;

    static_assert(SIG_PART_SIZE <= MAX_SCRIPT_ELEMENT_SIZE);
    static_assert(SF_INDICATOR_SIZE + SL_BODY_SIZE == SL_SIGNATURE_SIZE);
    static_assert(SF_INDICATOR_SIZE + sf_body_size(1) == SF_SIGNATURE_SIZE_MIN);
    static_assert(SF_INDICATOR_SIZE + sf_body_size(FXMSS_HEIGHT) == SF_SIGNATURE_SIZE_MAX);

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
            ~SecretKey();
            SecretKey(const SecretKey&) = default;
            SecretKey& operator=(const SecretKey&) = default;
            SecretKey(SecretKey&& other);
            SecretKey& operator=(SecretKey&& other);

            void Wipe();
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

#endif // BITCOIN_CRYPTO_SHRINCS_SHRINCS_H
