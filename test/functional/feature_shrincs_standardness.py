#!/usr/bin/env python3
# Copyright (c) 2026 The Elements developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that the SHRINCS witness layout is relayable.

Relay policy caps a witness stack before any script is run, in IsWitnessStandard():

  - P2WSH:     MAX_STANDARD_P2WSH_STACK_ITEM_SIZE     = 80 bytes per element,
               MAX_STANDARD_P2WSH_STACK_ITEMS         = 100 elements
  - tapscript: MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80 bytes per element

This is why the ELIP cuts a SHRINCS signature uniformly at 80 bytes rather than at
a structural boundary, where the WOTS+C chains alone would be a 514-byte element
that consensus allows but no node relays.

The first half spends outputs whose witness stack has the exact shape and element
count of a SHRINCS signature, under a script that drops the stack and succeeds.
That isolates the policy question from signature verification: a spend that policy
accepts lands in the mempool, and one it rejects gives bad-witness-nonstandard.

The second half runs the same witnesses through OP_SHRINCS itself. The elements are
junk, so no signature can verify — but each malformed layout stops the interpreter
at a different point, and the reject reason names which, so the parser is what is
under test rather than the verifier. A valid signature cannot be built here: this
framework has no SHRINCS signer. Verification proper is covered by the unit tests
in src/test/script_tests.cpp and end to end by feature_blocksign.py.
"""

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.key import ECKey
from test_framework.script import (
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    OP_DROP,
    OP_NOP4,
    OP_TRUE,
    taproot_construct,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# OP_SHRINCS replaces OP_NOP4 (0xb3); the test framework still spells it OP_NOP4.
OP_SHRINCS = OP_NOP4

# A SHRINCS public key is PK.seed || PK.sl || PK.sf.
SHRINCS_PUBKEY = bytes(48)

FEE = 1000
FUND = 50000

# The signature is cut into parts of this size, the last one carrying the remainder.
SIG_PART_SIZE = 80

# Bodies of a signature as the ELIP defines them: the serialization less its leading
# indicator byte, which q determines and the witness does not carry.
#   stateful, q = 1: R (16) || leaf_index (1) || wots+c (514) || mp_1 (16)
#   stateless:       SPHX_SIGNATURE_SIZE
SF_Q1_BODY = 16 + 1 + 514 + 16
SL_BODY = 5776


def parts(body_size):
    """Part sizes for a signature body: N - 1 full parts, then the remainder."""
    full, rest = divmod(body_size, SIG_PART_SIZE)
    return [SIG_PART_SIZE] * full + ([rest] if rest else [])


def slot(part_sizes):
    """One opcode's worth of witness: the parts, the SIGHASH byte, then q on top.

    The values are junk; only the sizes and the element count matter here. Every
    element is non-zero so that none is accidentally an empty vector.
    """
    return [bytes([0x42]) * n for n in part_sizes] + [b"\x01", b"\x01"]


class ShrincsStandardnessTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # No -acceptnonstdtxn: we want the default policy, which is what a
        # relaying node on the network runs.
        self.extra_args = [[]]

    def mempool_reason(self, tx):
        """Return the reject-reason testmempoolaccept gives for tx, or None if accepted."""
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]
        self.log.info("  -> allowed=%s reason=%s", result["allowed"], result.get("reject-reason"))
        return None if result["allowed"] else result["reject-reason"]

    def fund(self, script_pubkey):
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pubkey, amount=FUND)
        self.generate(self.nodes[0], 1)
        return COutPoint(int(funding["txid"], 16), funding["sent_vout"])

    def spend(self, outpoint, witness_stack):
        def build(fee):
            tx = CTransaction()
            tx.vin.append(CTxIn(outpoint, b""))
            tx.vout.append(CTxOut(FUND - fee, script_to_p2wsh_script(CScript([OP_TRUE]))))
            tx.vout.append(CTxOut(fee))  # ELEMENTS: explicit fee output
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
            tx.rehash()
            return tx

        # A stateless signature runs to several kilobytes, so a flat fee would trip
        # the min relay fee and hide the policy answer this test is after. One sat per
        # serialized byte overpays comfortably at any of these sizes.
        return build(max(FEE, len(build(FEE).serialize())))

    def p2wsh_relay(self, stack):
        """Try to relay a P2WSH spend whose witness stack is `stack`."""
        # A script that consumes exactly the supplied elements and succeeds, so the
        # only thing that can reject the spend is policy on the witness itself.
        script = CScript([OP_DROP] * len(stack) + [OP_TRUE])
        outpoint = self.fund(script_to_p2wsh_script(script))
        return self.mempool_reason(self.spend(outpoint, stack + [script]))

    def tapscript_relay(self, stack):
        """Try to relay a tapscript script-path spend whose witness stack is `stack`."""
        script = CScript([OP_DROP] * len(stack) + [OP_TRUE])
        internal = ECKey()
        internal.generate()
        internal_xonly = internal.get_pubkey().get_bytes()[1:]
        taproot = taproot_construct(internal_xonly, [("shrincs", script, LEAF_VERSION_TAPSCRIPT)])
        leaf = taproot.leaves["shrincs"]
        control_block = bytes([leaf.version + taproot.negflag]) + taproot.internal_pubkey + leaf.merklebranch

        outpoint = self.fund(taproot.scriptPubKey)
        return self.mempool_reason(self.spend(outpoint, stack + [bytes(script), control_block]))

    def shrincs_reason(self, stack, pubkey=SHRINCS_PUBKEY):
        """Relay a P2WSH spend that actually runs OP_SHRINCS over `stack`.

        The signature is junk, so it can never verify; what the reject reason shows is
        how far the interpreter got parsing the witness before it gave up.
        """
        script = CScript([pubkey, OP_SHRINCS])
        outpoint = self.fund(script_to_p2wsh_script(script))
        return self.mempool_reason(self.spend(outpoint, stack + [script]))

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 110)

        sf_slot = slot(parts(SF_Q1_BODY))
        sl_slot = slot(parts(SL_BODY))

        # 9 and 75 elements: the part count plus the SIGHASH byte and q.
        assert_equal(len(sf_slot), 9)
        assert_equal(len(sl_slot), 75)
        assert max(len(e) for e in sf_slot + sl_slot) == SIG_PART_SIZE

        self.log.info("A stateful signature at q = 1 relays, on both witness paths")
        assert_equal(self.p2wsh_relay(sf_slot), None)
        assert_equal(self.tapscript_relay(sf_slot), None)

        self.log.info("So does a stateless one, at 75 of the 100 elements P2WSH allows")
        assert_equal(self.p2wsh_relay(sl_slot), None)
        assert_equal(self.tapscript_relay(sl_slot), None)

        self.log.info("Two stateless signatures exceed the 100-element P2WSH cap")
        assert_equal(self.p2wsh_relay(sl_slot * 2), "bad-witness-nonstandard")

        self.log.info("Tapscript has no element cap, so two of them relay there")
        assert_equal(self.tapscript_relay(sl_slot * 2), None)

        self.log.info("One byte over the 80-byte cap is enough to stop a spend relaying")
        assert_equal(self.p2wsh_relay(slot([SIG_PART_SIZE + 1])), "bad-witness-nonstandard")
        assert_equal(self.tapscript_relay(slot([SIG_PART_SIZE + 1])), "bad-witness-nonstandard")

        # Past policy, the interpreter parses the witness. None of these signatures can
        # verify, so each reject reason names the point at which the parser stopped.
        def failed(script_error):
            return "mandatory-script-verify-flag-failed (%s)" % script_error

        self.log.info("A well-formed slot parses and reaches verification, which it fails")
        assert_equal(self.shrincs_reason(sf_slot),
                     failed("Signature must be zero for failed CHECK(MULTI)SIG operation"))

        self.log.info("A last part one byte short of what q names is caught by the parser")
        short_sizes = parts(SF_Q1_BODY)
        short_sizes[-1] -= 1
        assert_equal(self.shrincs_reason(slot(short_sizes)),
                     failed("Invalid SHRINCS signature element size"))

        self.log.info("So is a byte moved across a cut point, which leaves the total intact")
        # Moved down rather than up: an 81-byte element would be stopped by policy
        # before the interpreter ever saw it.
        moved_sizes = parts(SF_Q1_BODY)
        moved_sizes[-2] -= 1
        moved_sizes[-1] += 1
        assert_equal(self.shrincs_reason(slot(moved_sizes)),
                     failed("Invalid SHRINCS signature element size"))

        self.log.info("q must be minimally encoded, whatever the verification flags")
        assert_equal(self.shrincs_reason(sf_slot[:-1] + [b"\x01\x00"]),
                     failed("Data push larger than necessary"))

        self.log.info("The SIGHASH byte is its own element and must be a defined hashtype")
        assert_equal(self.shrincs_reason(sf_slot[:-2] + [b"\x05", b"\x01"]),
                     failed("Invalid Schnorr signature hash type"))

        self.log.info("A public key that is not 48 bytes fails before the signature is parsed")
        assert_equal(self.shrincs_reason(sf_slot, pubkey=SHRINCS_PUBKEY[:-1]),
                     failed("Public key is neither compressed or uncompressed"))

        self.log.info("q = 0 is 'did not sign': false without aborting the script")
        assert_equal(self.shrincs_reason([b""]),
                     failed("Script evaluated without error but finished with a false/empty top stack element"))


if __name__ == "__main__":
    ShrincsStandardnessTest(__file__).main()
