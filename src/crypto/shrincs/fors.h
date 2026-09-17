#ifndef BITCOIN_CRYPTO_SHRINCS_FORS_H
#define BITCOIN_CRYPTO_SHRINCS_FORS_H

#include <crypto/shrincs/address.h>
#include <crypto/shrincs/constants.h>
#include <crypto/shrincs/hash.h>
#include <crypto/shrincs/wots.h>

using namespace Parameters;
using namespace AddressTypes;
using namespace Address;
using namespace HASH;

namespace FORS
{
    void fors_sk_gen(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t node_index, unsigned char* out);
    void fors_node(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t node_index, uint32_t node_height, unsigned char* out);
    void fors_sign(const unsigned char* sk_seed, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);
    void fors_pk_from_sig(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);
}

#endif // BITCOIN_CRYPTO_SHRINCS_FORS_H
