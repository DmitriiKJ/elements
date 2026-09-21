#!/usr/bin/env python3
# Copyright (c) 2026 The Elements developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the version-bits deployment that enables OP_SHRINCS / OP_SHRINCSADD.

Until the "shrincs" deployment is active the two opcodes keep their historical
OP_NOP4 / OP_NOP5 semantics: consensus treats them as no-ops and relay policy
refuses them as upgradable NOPs. Once the deployment is active they verify
SHRINCS signatures.

Before activation:

  policy     any such spend is refused as an upgradable NOP
  consensus  P2SH <pk> OP_SHRINCS: the NOP leaves the pubkey on top, so the
             spend is VALID and anyone can take the coins;
             P2WSH <pk> OP_SHRINCS: the NOP leaves the signature on the stack
             and the witness cleanstack rule rejects the spend.

After activation both are parsed and checked, and the junk signature fails.

The P2WSH case is worth reading twice: a node without the deployment does not
merely skip the signature check, it rejects the spend outright. Enabling the
opcodes therefore has to be coordinated, which is what the deployment is for.

The deployment follows the usual Elements version-bits path (defined ->
started -> locked_in -> active) signalling on bit 22, as
feature_elements_simplicity_activation.py checks for Simplicity.
"""

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_NOP4,
    OP_TRUE,
)
from test_framework.script_util import script_to_p2sh_script, script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

# OP_SHRINCS replaces OP_NOP4 (0xb3); the test framework still spells it OP_NOP4.
OP_SHRINCS = OP_NOP4

# Any 48 bytes will do for a key that never verifies; not all zeros, so that under
# OP_NOP4 semantics the pubkey left on top of a legacy stack casts to true.
SHRINCS_PUBKEY = bytes([0x01]) * 48
SHRINCS_BIT = 22
SIG_PART_SIZE = 80
SF_Q1_BODY = 16 + 1 + 514 + 16  # R || leaf_index || wots+c || one Merkle path element

FEE = 1000
FUND = 50000

# regtest overrides the period and threshold of the shrincs deployment to 128 blocks
PERIOD = 128
START_HEIGHT = 500

NOP_POLICY = "mempool-script-verify-flag-failed (NOPx reserved for soft-fork upgrades)"
NOP_CLEANSTACK = "Stack size must be exactly one after execution"
CHECKED = "Signature must be zero for failed CHECK(MULTI)SIG operation"


def junk_signature_parts():
    """The seven 80-byte parts of an OP_SHRINCS signature at q = 1, with junk contents."""
    full, rest = divmod(SF_Q1_BODY, SIG_PART_SIZE)
    sizes = [SIG_PART_SIZE] * full + ([rest] if rest else [])
    return [bytes([0x42]) * n for n in sizes]


class ShrincsActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-evbparams=shrincs:%d:::" % START_HEIGHT]]

    def status(self):
        return self.nodes[0].getdeploymentinfo()["deployments"]["shrincs"]["bip9"]["status"]

    def fund(self, script_pubkey):
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pubkey, amount=FUND)
        self.generate(self.nodes[0], 1)
        return COutPoint(int(funding["txid"], 16), funding["sent_vout"])

    def base_tx(self, outpoint):
        tx = CTransaction()
        tx.vin.append(CTxIn(outpoint, b""))
        tx.vout.append(CTxOut(FUND - FEE, script_to_p2wsh_script(CScript([OP_TRUE]))))
        tx.vout.append(CTxOut(FEE))  # ELEMENTS: explicit fee output
        return tx

    def p2wsh_spend(self, outpoint, script):
        tx = self.base_tx(outpoint)
        tx.wit.vtxinwit.append(CTxInWitness())
        # parts, SIGHASH byte, q, then the witness script
        tx.wit.vtxinwit[0].scriptWitness.stack = junk_signature_parts() + [b"\x01", b"\x01", script]
        tx.rehash()
        return tx

    def p2sh_spend(self, outpoint, script):
        tx = self.base_tx(outpoint)
        # Integer 1 encodes as OP_1, the minimal push of the single byte 0x01 that
        # both the SIGHASH byte and q are.
        tx.vin[0].scriptSig = CScript(junk_signature_parts() + [1, 1, bytes(script)])
        tx.rehash()
        return tx

    def mempool_reason(self, tx):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]
        return None if result["allowed"] else result["reject-reason"]

    def assert_block_rejects(self, tx, script_error):
        assert_raises_rpc_error(-25, script_error, self.generateblock,
                                self.nodes[0], self.wallet.get_address(), [tx.serialize().hex()])

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        script = CScript([SHRINCS_PUBKEY, OP_SHRINCS])
        p2sh = script_to_p2sh_script(script)
        p2wsh = script_to_p2wsh_script(script)

        self.generate(self.wallet, 110)
        assert_equal(self.status(), "defined")
        p2sh_before, p2sh_after = self.fund(p2sh), self.fund(p2sh)
        p2wsh_out = self.fund(p2wsh)

        self.log.info("Before the deployment starts, OP_SHRINCS is OP_NOP4")
        assert_equal(self.mempool_reason(self.p2sh_spend(p2sh_before, script)), NOP_POLICY)
        assert_equal(self.mempool_reason(self.p2wsh_spend(p2wsh_out, script)), NOP_POLICY)

        self.log.info("Under pre-activation consensus a P2WSH spend fails cleanstack ...")
        self.assert_block_rejects(self.p2wsh_spend(p2wsh_out, script), NOP_CLEANSTACK)

        self.log.info("... and a P2SH spend is valid with any signature at all")
        self.generateblock(node, self.wallet.get_address(), [self.p2sh_spend(p2sh_before, script).serialize().hex()])
        assert_equal(node.gettxout(p2sh_before.hash.to_bytes(32, "big").hex(), p2sh_before.n), None)

        self.log.info("The deployment starts at the first period boundary at or after height %d" % START_HEIGHT)
        started_at = PERIOD * ((START_HEIGHT + PERIOD - 1) // PERIOD)
        self.generate(self.wallet, started_at - node.getblockcount())
        assert_equal(self.status(), "started")

        self.log.info("Every block of the started period signals on bit %d" % SHRINCS_BIT)
        for block in self.generate(self.wallet, PERIOD):
            version = int(node.getblockheader(block)["versionHex"], 16)
            assert version & (1 << SHRINCS_BIT), "block does not signal for shrincs"
        assert_equal(self.status(), "locked_in")

        self.log.info("While locked in, the opcode is still OP_NOP4")
        assert_equal(self.mempool_reason(self.p2sh_spend(p2sh_after, script)), NOP_POLICY)
        self.assert_block_rejects(self.p2wsh_spend(p2wsh_out, script), NOP_CLEANSTACK)

        self.log.info("One more period and the deployment is active")
        self.generate(self.wallet, PERIOD)
        assert_equal(self.status(), "active")
        assert_equal(node.getdeploymentinfo()["deployments"]["shrincs"]["active"], True)

        self.log.info("Now the same spends are parsed and verified as SHRINCS signatures")
        assert_equal(self.mempool_reason(self.p2sh_spend(p2sh_after, script)),
                     "mempool-script-verify-flag-failed (%s)" % CHECKED)
        assert_equal(self.mempool_reason(self.p2wsh_spend(p2wsh_out, script)),
                     "mempool-script-verify-flag-failed (%s)" % CHECKED)
        self.assert_block_rejects(self.p2sh_spend(p2sh_after, script), CHECKED)
        self.assert_block_rejects(self.p2wsh_spend(p2wsh_out, script), CHECKED)

        self.log.info("Once active, signalling stops")
        block = self.generate(self.wallet, 1)[0]
        assert_equal(int(node.getblockheader(block)["versionHex"], 16) & (1 << SHRINCS_BIT), 0)


if __name__ == "__main__":
    ShrincsActivationTest(__file__).main()
