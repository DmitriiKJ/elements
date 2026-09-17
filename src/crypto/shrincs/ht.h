#ifndef BITCOIN_CRYPTO_SHRINCS_HT_H
#define BITCOIN_CRYPTO_SHRINCS_HT_H

#include <crypto/shrincs/xmss.h>

using namespace XMSS;

namespace HT
{
    void hypertree_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, uint64_t tree_index, uint32_t leaf_index, unsigned char* out);
    bool hypertree_verify(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, uint64_t tree_index, uint32_t leaf_index, const unsigned char* sl_root);

}

#endif // BITCOIN_CRYPTO_SHRINCS_HT_H
