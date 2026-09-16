#!/usr/bin/env python3
# Copyright (c) 2026 The Elements developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Spend real SHRINCS signatures through OP_SHRINCS and OP_SHRINCSADD.

The transactions are fixed hex, signed once and stored in data/shrincs_spends.json.
They can be, because nothing about them is random: the chain starts at the
elementsregtest genesis, whose -initialfreecoins output has an outpoint fixed by the
consensus arguments below, the funding transaction spends that output and is signed by
nobody, and each spend is a fixed transaction over a fixed prevout. Change any of the
arguments in extra_args and the genesis output moves, which the first assertion in
run_test() reports rather than leaving the failure to surface as a bad signature.

Three spends are exercised, all P2WSH:

  <pk1> OP_SHRINCS                                   a stateful signature at q = 1
  <pk1> OP_SHRINCS                                   a stateless signature
  <pk1> OP_SHRINCS <pk2> OP_SHRINCSADD               2-of-3: pk1 signs stateful, pk2
  <pk3> OP_SHRINCSADD OP_2 OP_NUMEQUAL               stateless, pk3 does not sign

The negative cases mutate the witness of a valid spend, which leaves the transaction id
alone, so each one is offered to testmempoolaccept before the valid spend is sent.

The vectors were produced by a throwaway unit test that builds these transactions with
SHRINCS keys from the seeds the unit tests use (salts 0x11, 0x22, 0x33 over the
unbalanced tree of depth 32), computes each WITNESS_V0 sighash and signs it. Python has
no SHRINCS signer, which is why the signatures are recorded rather than made here.
"""

import json
import os

from test_framework.messages import tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# The genesis free-coins output, fixed by the consensus arguments in extra_args.
GENESIS_COINS_TXID = "027f015923d266ffb8af1fadd09a3743dffebd199e8f1e45c96ca12e58992d5f"

# Witness layout of a stateful spend at q = 1, bottom to top: seven signature parts, the
# SIGHASH byte, q, and the witness script.
Q = -2
SIGHASH_BYTE = -3
LAST_PART = -4
FIRST_PART = 0


def failed(script_error):
    return "mempool-script-verify-flag-failed (%s)" % script_error


class ShrincsSpendTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # These fix the genesis block, and with it every txid in the vectors.
        self.extra_args = [[
            "-initialfreecoins=2100000000000000",
            "-anyonecanspendaremine=1",
            "-con_connect_genesis_outputs=1",
            "-validatepegin=0",
        ]]

    def mempool_reason(self, tx_hex):
        """Return the reject-reason testmempoolaccept gives, or None if accepted."""
        result = self.nodes[0].testmempoolaccept([tx_hex], maxfeerate=0)[0]
        return None if result["allowed"] else result["reject-reason"]

    def mutate(self, tx_hex, index, element):
        """Replace one witness element of a spend, leaving the transaction id alone."""
        tx = tx_from_hex(tx_hex)
        tx.wit.vtxinwit[0].scriptWitness.stack[index] = element
        return tx.serialize().hex()

    def send(self, tx_hex, name):
        txid = self.nodes[0].sendrawtransaction(tx_hex, 0)
        self.log.info("  %s accepted as %s", name, txid)
        return txid

    def run_test(self):
        node = self.nodes[0]
        vectors = json.load(open(os.path.join(os.path.dirname(__file__), "data", "shrincs_spends.json"), encoding="utf-8"))

        assert node.gettxout(GENESIS_COINS_TXID, 0) is not None, (
            "genesis free-coins output %s is missing, so the consensus arguments no "
            "longer match the ones the vectors were signed under" % GENESIS_COINS_TXID)

        self.wallet = MiniWallet(node)

        self.log.info("Funding three SHRINCS outputs from the genesis free coins")
        fund_txid = self.send(vectors["fund"], "funding")
        self.generate(self.wallet, 1)
        for vout in range(3):
            assert_equal(node.gettxout(fund_txid, vout)["confirmations"], 1)

        stateful = vectors["spends"]["stateful"]

        self.log.info("A tampered witness never verifies, and says where it stopped")
        tx = tx_from_hex(stateful)
        stack = tx.wit.vtxinwit[0].scriptWitness.stack

        corrupt = bytearray(stack[FIRST_PART])
        corrupt[0] ^= 1
        assert_equal(self.mempool_reason(self.mutate(stateful, FIRST_PART, bytes(corrupt))),
                     failed("Signature must be zero for failed CHECK(MULTI)SIG operation"))

        assert_equal(self.mempool_reason(self.mutate(stateful, LAST_PART, stack[LAST_PART][:-1])),
                     failed("Invalid SHRINCS signature element size"))

        assert_equal(self.mempool_reason(self.mutate(stateful, Q, b"\x01\x00")),
                     failed("Data push larger than necessary"))

        assert_equal(self.mempool_reason(self.mutate(stateful, SIGHASH_BYTE, b"\x05")),
                     failed("Invalid Schnorr signature hash type"))

        self.log.info("The signatures themselves verify and the spends confirm")
        spent = [self.send(stateful, "stateful"),
                 self.send(vectors["spends"]["stateless"], "stateless"),
                 self.send(vectors["spends"]["threshold"], "2-of-3 threshold")]

        self.generate(self.wallet, 1)
        for txid in spent:
            assert_equal(node.gettxout(txid, 0)["confirmations"], 1)

        # Every funded output is gone, so each spend was accepted for the output it names
        # rather than all three landing on one.
        for vout in range(3):
            assert node.gettxout(fund_txid, vout) is None


if __name__ == "__main__":
    ShrincsSpendTest(__file__).main()
