#!/usr/bin/env python3
# Copyright (c) 2026 The Elements developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the DropKick commit/reveal rescue of quantum-vulnerable outputs."""

import copy
from io import BytesIO

from test_framework.crypto import shrincs
from test_framework.crypto.bip32 import HARDENED, ExtKey
from test_framework.dropkick import (
    COMMITMENT_DEPTH,
    OUT_P2PKH,
    OUT_P2SH,
    OUT_P2SH_P2WPKH,
    OUT_P2WPKH,
    OUT_P2WSH,
    WIT_PUBKEY,
    WIT_SCRIPT,
    WIT_XPRV,
    DropKickAnchor,
    DropKickClaim,
    DropKickPayload,
    DropKickWitness,
    build_agg_tree,
    commitment,
    dropkick_sighash,
    make_publication_script,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTxInWitness,
    CTxOutValue,
    CTransaction,
    CTxIn,
    CTxOut,
    hash256,
    ser_string,
)
from test_framework.key import ECKey
from test_framework.script import (
    CScript,
    OP_0,
    OP_2,
    OP_3,
    OP_EQUAL,
    OP_RETURN,
    OP_TRUE,
    hash160,
    sign_input_legacy,
    sign_input_segwitv0,
)
from test_framework.script_util import (
    key_to_p2pkh_script,
    key_to_p2sh_p2wpkh_script,
    key_to_p2wpkh_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

FEE = 1000

REVEAL_FEE = 40000
FUND = 200000

# regtest overrides the dropkick deployment to 128-block periods
PERIOD = 128
START_HEIGHT = 256

REDEEM = CScript([OP_TRUE])
P2SH_SPK = script_to_p2sh_script(REDEEM)

# Distinct redeem scripts, so that witness records cannot be confused with one
# another. Each leaves exactly one true item, which P2SH cleanstack requires.
REDEEM_A = CScript([OP_2, OP_2, OP_EQUAL])
REDEEM_B = CScript([OP_3, OP_3, OP_EQUAL])

UNCLAIMED = "dropkick-unclaimed-input"
MAX_MONEY = 21000000 * COIN

def witness_stripped(raw_hex):
    """The serialisation an anchor carries: the form the txid is taken over."""
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(raw_hex)))
    return tx.serialize_without_witness()

def _eckey(secret):
    """Wrap a raw 32-byte secret as the signing key the framework expects."""
    key = ECKey()
    key.set(secret, True)
    return key

def p2sh_script_input(redeem):
    """P2SH of a script that needs no signature at all."""
    return {
        "spk": script_to_p2sh_script(redeem),
        "witness": ser_string(redeem),
        "wit_type": WIT_SCRIPT,
        "out_type": OUT_P2SH,
        "path": [],
        "prepare": lambda tx, i: tx.vin[i].__setattr__("scriptSig", CScript([bytes(redeem)])),
        "sign": lambda tx, i, amount: None,
    }

def p2wsh_script_input(script):
    """P2WSH of a script that needs no signature.

    The only output type whose statement is 32 bytes and a plain SHA256 rather
    than a hash160, which makes it the odd row of the sec:ka table.
    """
    return {
        "spk": script_to_p2wsh_script(script),
        "witness": ser_string(script),
        "wit_type": WIT_SCRIPT,
        "out_type": OUT_P2WSH,
        "path": [],
        "prepare": lambda tx, i: tx.wit.vtxinwit[i].scriptWitness.stack.__init__([bytes(script)]),
        "sign": lambda tx, i, amount: None,
    }

def p2pkh_input(key):
    pub = key.get_pubkey().get_bytes()
    return {
        "spk": key_to_p2pkh_script(pub),
        "witness": pub,
        "wit_type": WIT_PUBKEY,
        "out_type": OUT_P2PKH,
        "path": [],
        "prepare": lambda tx, i: tx.vin[i].__setattr__("scriptSig", CScript([pub])),
        "sign": lambda tx, i, amount: sign_input_legacy(tx, i, key_to_p2pkh_script(pub), key),
    }

def p2wpkh_input(key):
    pub = key.get_pubkey().get_bytes()

    def sign(tx, i, amount):
        # BIP143 hashes the P2PKH-shaped script code, not the witness program.
        sign_input_segwitv0(tx, i, key_to_p2pkh_script(pub), amount, key)

    def prepare(tx, i):
        tx.wit.vtxinwit[i].scriptWitness.stack = [pub]

    return {
        "spk": key_to_p2wpkh_script(pub),
        "witness": pub,
        "wit_type": WIT_PUBKEY,
        "out_type": OUT_P2WPKH,
        "path": [],
        "prepare": prepare,
        "sign": sign,
    }

def xprv_input(xkey, path, kind="p2wpkh"):
    """An input unlocked by deriving a child of an extended private key.

    The witness is the 78-byte BIP32 serialisation; the claim carries the path,
    and the node derives the same child before applying the row of sec:ka.
    """
    child = xkey.derive_path(path)
    inner = {"p2pkh": p2pkh_input, "p2wpkh": p2wpkh_input}[kind](_eckey(child.secret))
    return dict(inner,
                witness=xkey.serialize(),
                wit_type=WIT_XPRV,
                path=path)

def p2sh_p2wpkh_input(key):
    pub = key.get_pubkey().get_bytes()
    redeem = CScript([OP_0, hash160(pub)])

    def prepare(tx, i):
        tx.vin[i].scriptSig = CScript([bytes(redeem)])
        tx.wit.vtxinwit[i].scriptWitness.stack = [pub]

    return {
        "spk": key_to_p2sh_p2wpkh_script(pub),
        "witness": pub,
        "wit_type": WIT_PUBKEY,
        "out_type": OUT_P2SH_P2WPKH,
        "path": [],
        "prepare": prepare,
        "sign": lambda tx, i, amount: sign_input_segwitv0(tx, i, key_to_p2pkh_script(pub), amount, key),
    }

class DropKickTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.rpc_timeout = 240
        self.setup_clean_chain = True
        self.extra_args = [[
            "-evbparams=dropkick:%d:::" % START_HEIGHT,
            # A reveal payload runs to several kilobytes; the default 83-byte
            # data carrier limit would refuse it before consensus saw it.
            "-datacarriersize=100000",
            "-txindex=1",
        ]]

    def status(self):
        return self.nodes[0].getdeploymentinfo()["deployments"]["dropkick"]["bip9"]["status"]

    def fund(self, script_pubkey, amount=FUND):
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pubkey, amount=amount)
        self.generate(self.wallet, 1)
        return COutPoint(int(funding["txid"], 16), funding["sent_vout"])

    def p2sh_spend(self, outpoint):
        """An ordinary spend of P2SH(OP_TRUE): no signature, no payload."""
        tx = CTransaction()
        tx.vin.append(CTxIn(outpoint, CScript([bytes(REDEEM)])))
        tx.vout.append(CTxOut(FUND - FEE, script_to_p2sh_script(REDEEM)))
        tx.vout.append(CTxOut(FEE))  # ELEMENTS: explicit fee output
        tx.rehash()
        return tx

    def advance_to(self, status):
        """Mine whole periods until the deployment reaches the wanted status."""
        while self.status() != status:
            self.generate(self.wallet, PERIOD)

    # --- commitment side -------------------------------------------------

    def publish_root(self, root):
        """Put an aggregation root on chain and return its funding outpoint."""
        published = self.wallet.send_to(
            from_node=self.nodes[0], scriptPubKey=make_publication_script(root), amount=0)
        self.generate(self.wallet, 1)
        return published["txid"]

    def build_anchor(self, txid):
        """Assemble the anchor that opens against a published root."""
        node = self.nodes[0]
        block_hash = node.getrawtransaction(txid, True)["blockhash"]
        block = node.getblock(block_hash)

        # Internal byte order everywhere: the RPC prints hashes reversed.
        txids = [bytes.fromhex(t)[::-1] for t in block["tx"]]
        index = block["tx"].index(txid)

        path, layer, pos = [], txids, index
        while len(layer) > 1:
            if len(layer) % 2:                      # odd level duplicates its last node
                layer = layer + [layer[-1]]
            path.append(layer[pos ^ 1])
            layer = [hash256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
            pos >>= 1
        assert_equal(layer[0].hex(), bytes.fromhex(block["merkleroot"])[::-1].hex())

        return DropKickAnchor(
            block_hash=bytes.fromhex(block_hash)[::-1],
            tx_index=index,
            tx_path=path,
            tx_data=witness_stripped(node.getrawtransaction(txid)),
        )

    # --- reveal side -----------------------------------------------------

    def build_reveal(self, rescues, payload, sk, state_ctr, *, fee=None, tx_mutator=None,
                     payload_index=None, late_payload_mutator=None):
        """Assemble, sign and return a reveal spending every rescued input.

        The order is the one of rem:signing-order: the payload goes in with an
        empty signature, the message is computed over that form, the payload is
        written back whole, and only then are the legacy signatures made - they
        commit to the outputs, and so to the post-quantum signature.
        """
        tx = CTransaction()
        for outpoint, spec, _ in rescues:
            tx.vin.append(CTxIn(outpoint, b""))
            tx.wit.vtxinwit.append(CTxInWitness())
        for i, (_, spec, _) in enumerate(rescues):
            spec["prepare"](tx, i)

        total = sum(amount for _, _, amount in rescues)
        fee = REVEAL_FEE if fee is None else fee

        owed = [0] * len(payload.salvagers)
        for w in payload.witnesses:
            if w.sv_idx and w.sv_idx <= len(owed):
                owed[w.sv_idx - 1] += w.sv_sat
        paid = 0
        for k, amount_owed in enumerate(owed):
            if amount_owed == 0:
                continue
            tx.vout.append(CTxOut(amount_owed, CScript(payload.salvagers[k])))
            paid += amount_owed

        built_index = len(tx.vout)
        tx.vout.append(CTxOut(0, payload.output_script()))
        tx.vout.append(CTxOut(total - fee - paid, script_to_p2sh_script(REDEEM)))
        tx.vout.append(CTxOut(fee))                          # ELEMENTS: explicit fee

        if tx_mutator is not None:
            tx_mutator(tx)

        payload_index = built_index if payload_index is None else payload_index

        if late_payload_mutator is not None:
            late_payload_mutator(payload)

        sighash = dropkick_sighash(tx, payload_index, payload)
        payload.sig = shrincs.shrincs_sign(sighash, b"", sk, state_ctr, None)
        assert payload.sig is not None, "signing failed"
        tx.vout[payload_index].scriptPubKey = payload.output_script()

        for i, (_, spec, amount) in enumerate(rescues):
            spec["sign"](tx, i, CTxOutValue(amount))
        tx.rehash()
        return tx

    def prepare(self, name, specs_per_witness, batches, amount=FUND,
                salvagers=None, sv_terms=None):
        """Publish the commitments for one scenario and fund what it rescues.

        Returns everything the reveal will need. Splitting this from the reveal
        lets every scenario share a single burial of COMMITMENT_DEPTH blocks,
        which is also how a real batch would work.

        `specs_per_witness` lists, for each witness record, the input kinds it
        opens; every kind in one entry must share the same witness, which is
        what lets a single public key unlock outputs of several types.
        `batches` groups the witness records into aggregation batches, one
        published root each, so a payload can carry one anchor or several.
        """
        sk, pk = shrincs.shrincs_keygen(bytes([len(name)]) * 48, bytes([0x00, 32]))

        salvagers = salvagers or []
        sv_terms = sv_terms or {}

        witnesses, wit_types = [], []
        for specs in specs_per_witness:
            assert len({bytes(s["witness"]) for s in specs}) == 1, "one record, one witness"
            witnesses.append(specs[0]["witness"])
            wit_types.append(specs[0]["wit_type"])
        terms = [sv_terms.get(j, (0, 0)) for j in range(len(witnesses))]
        commits = [
            commitment(w, pk,
                       b"" if sv_idx == 0 else bytes(salvagers[sv_idx - 1]),
                       sv_sat)
            for w, (sv_idx, sv_sat) in zip(witnesses, terms)
        ]

        anchors, records, pub_txids = [], [], []
        for batch in batches:
            root, paths = build_agg_tree([commits[j] for j in batch])
            txid = self.publish_root(root)
            pub_txids.append(txid)
            anchors.append(self.build_anchor(txid))
            for leaf_index, j in enumerate(batch):
                sv_idx, sv_sat = terms[j]
                records.append((j, DropKickWitness(
                    anchor_idx=len(anchors) - 1, sv_idx=sv_idx, sv_sat=sv_sat,
                    leaf_index=leaf_index, agg_path=paths[leaf_index],
                    wit_type=wit_types[j], wit_data=witnesses[j])))

        order = {j: pos for pos, (j, _) in enumerate(records)}

        rescues, claims = [], []
        for j, specs in enumerate(specs_per_witness):
            for spec in specs:
                rescues.append((self.fund(spec["spk"], amount), spec, amount))
                claims.append(DropKickClaim(
                    input_idx=len(rescues) - 1, wit_idx=order[j],
                    out_type=spec["out_type"], path=spec["path"]))

        payload = DropKickPayload()
        payload.pk_pq = pk
        payload.anchors = anchors
        payload.salvagers = [bytes(s) for s in salvagers]
        payload.witnesses = [w for _, w in records]
        payload.claims = claims
        return {"name": name, "sk": sk, "payload": payload, "rescues": rescues,
                "pub_txids": pub_txids}

    def reveal(self, ctx, state_ctr, *, fee=None):
        """Sign and broadcast the reveal a prepared scenario calls for."""
        node = self.nodes[0]
        tx = self.build_reveal(ctx["rescues"], ctx["payload"], ctx["sk"], state_ctr, fee=fee)
        node.sendrawtransaction(tx.serialize().hex())
        self.generate(self.wallet, 1)
        for outpoint, _, _ in ctx["rescues"]:
            assert_equal(node.gettxout(outpoint.hash.to_bytes(32, "big").hex(), outpoint.n), None)
        return tx

    def expect_reject(self, ctx, reason, *, payload_mutator=None, tx_mutator=None,
                      state_ctr=1, fee=None, break_signature=False, payload_index=None,
                      late_payload_mutator=None):
        """Assert that a scenario, once broken in one way, is refused.

        The payload is mutated and then signed afresh, so that the rule under
        test is the one that fires rather than the signature check catching a
        message that no longer matches.
        """
        payload = copy.deepcopy(ctx["payload"])
        if payload_mutator is not None:
            payload_mutator(payload)

        tx = self.build_reveal(ctx["rescues"], payload, ctx["sk"], state_ctr,
                               fee=fee, tx_mutator=tx_mutator, payload_index=payload_index,
                               late_payload_mutator=late_payload_mutator)
        if break_signature:
            payload.sig = bytes([payload.sig[0] ^ 0xff]) + payload.sig[1:]
            index = next(i for i, o in enumerate(tx.vout)
                         if bytes(o.scriptPubKey)[:1] == bytes([OP_RETURN]))
            tx.vout[index].scriptPubKey = payload.output_script()
            tx.rehash()

        assert_raises_rpc_error(-26, reason, self.nodes[0].sendrawtransaction,
                                tx.serialize().hex(), 0.10, 21000000)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 120)

        self.log.info("The deployment starts out defined and inactive")
        assert_equal(self.status(), "defined")

        self.log.info("A hash-protected output spends freely before activation")
        before = self.fund(P2SH_SPK)
        tx = self.p2sh_spend(before)
        node.sendrawtransaction(tx.serialize().hex())
        self.generate(self.wallet, 1)

        self.log.info("Fund the outputs the later stages will rescue, while that is still possible")
        pending = [self.fund(P2SH_SPK) for _ in range(2)]

        self.log.info("Signal the deployment through to active")
        self.advance_to("active")
        assert_equal(self.status(), "active")

        self.log.info("Now the same spend is refused: no claim names the input")
        tx = self.p2sh_spend(pending[0])
        assert_raises_rpc_error(-26, UNCLAIMED, node.sendrawtransaction, tx.serialize().hex())

        self.log.info("An output with no knowledge asymmetry is unaffected")

        self.wallet.send_self_transfer(from_node=node)
        self.generate(self.wallet, 1)

        assert_equal(len(node.getrawmempool()), 0)

        self.log.info("--- the reveal matrix ---")

        key_a, key_b, key_u = ECKey(), ECKey(), ECKey()
        key_a.generate()
        key_b.generate()
        key_u.generate(compressed=False)
        xkey = ExtKey.from_seed(b"dropkick test seed")

        sv_one = script_to_p2sh_script(REDEEM_A)
        sv_two = script_to_p2sh_script(REDEEM_B)

        scenarios = [
            ("wit 0x01: one public key, one P2PKH input",
             [[p2pkh_input(key_a)]], [[0]], 1),
            ("wit 0x01: the same key over P2PKH, P2WPKH and P2SH-P2WPKH at once",
             [[p2pkh_input(key_a), p2wpkh_input(key_a), p2sh_p2wpkh_input(key_a)]], [[0]], 1),
            ("wit 0x01: an uncompressed public key over P2PKH",
             [[p2pkh_input(key_u)]], [[0]], 1),
            ("wit 0x01: a P2WPKH input on its own",
             [[p2wpkh_input(key_a)]], [[0]], 1),
            ("wit 0x01: two keys, two records, one batch",
             [[p2pkh_input(key_a)], [p2wpkh_input(key_b)]], [[0, 1]], 1),
            ("wit 0x01: two keys in separate batches, so two anchors",
             [[p2wpkh_input(key_a)], [p2sh_p2wpkh_input(key_b)]], [[0], [1]], 1),
            ("wit 0x03: a script-locked P2SH input",
             [[p2sh_script_input(REDEEM)]], [[0]], 1),
            ("wit 0x03: with a stateless signature",
             [[p2sh_script_input(REDEEM_A)]], [[0]], None),
            ("wit 0x03: from a different state counter",
             [[p2sh_script_input(REDEEM_B)]], [[0]], 7),
            ("wit 0x03: a P2WSH input, the one type with a 32-byte statement",
             [[p2wsh_script_input(REDEEM_A)]], [[0]], 1),
            ("wit 0x03: P2SH and P2WSH of the same script under one record",
             [[p2sh_script_input(REDEEM_B), p2wsh_script_input(REDEEM_B)]], [[0]], 1),
            ("wit 0x02: an extended key derived down a hardened path",
             [[xprv_input(xkey, [84 | HARDENED, 0 | HARDENED, 0])]], [[0]], 1),
            ("wit 0x02: one extended key over two children and two output types",
             [[xprv_input(xkey, [0, 1], "p2pkh"),
               xprv_input(xkey, [0, 2], "p2wpkh")]], [[0]], 1),
        ]

        self.log.info("Publish every commitment first, then bury them all together")
        prepared = [(self.prepare(str(i), scripts, batches), ctr)
                    for i, (_, scripts, batches, ctr) in enumerate(scenarios)]

        salvaged = self.prepare(
            "salv",
            [[p2sh_script_input(REDEEM)],
             [p2pkh_input(key_b)],
             [xprv_input(xkey, [7])]],
            [[0, 1, 2]],
            salvagers=[sv_one, sv_two],
            sv_terms={0: (1, 3000), 1: (2, 5000), 2: (2, 7000)})

        salv_bad = self.prepare(
            "salvneg",
            [[p2sh_script_input(REDEEM_A)],
             [p2wpkh_input(key_b)]],
            [[0, 1]],
            salvagers=[sv_one, sv_two],
            sv_terms={0: (1, 3000), 1: (2, 5000)})

        bad = self.prepare("neg", [[p2pkh_input(key_a), p2wpkh_input(key_a)]], [[0]])

        rich = self.prepare("rich", [[p2sh_script_input(REDEEM_B)]], [[0]], amount=50_000_000)
        required = 50_000_000 // 1000

        self.generate(self.wallet, COMMITMENT_DEPTH)

        for (label, _, _, _), (ctx, ctr) in zip(scenarios, prepared):
            self.log.info(label)
            tx = self.reveal(ctx, ctr)
            assert_equal(len(tx.vin), len(ctx["rescues"]))

        self.log.info("salvagers: one entry owed one commitment, the other owed two")
        tx = self.reveal(salvaged, 1)

        assert_equal(tx.vout[0].nValue.getAmount(), 3000)
        assert_equal(bytes(tx.vout[0].scriptPubKey), bytes(sv_one))
        assert_equal(tx.vout[1].nValue.getAmount(), 5000 + 7000)
        assert_equal(bytes(tx.vout[1].scriptPubKey), bytes(sv_two))
        assert_equal(bytes(tx.vout[2].scriptPubKey)[:1], bytes([OP_RETURN]))

        self.log.info("The stateless path costs an order of magnitude more signature")
        stateful = [c["payload"].sig for c, q in prepared if q is not None]
        stateless = [c["payload"].sig for c, q in prepared if q is None]
        assert_greater_than(min(len(s) for s in stateless), 5000)
        assert_greater_than(1000, max(len(s) for s in stateful))

        self.log.info("--- rule rejections ---")

        def drop_anchors(p):
            p.anchors = []

        def long_path(p):
            p.anchors[0].tx_path = p.anchors[0].tx_path + [bytes(32)] * 17

        def claim_outside(p):
            p.claims[0].input_idx = 99

        def claim_twice(p):
            p.claims[1].input_idx = p.claims[0].input_idx

        def paid_self_salvage(p):
            p.witnesses[0].sv_sat = 1

        def unknown_block(p):
            p.anchors[0].block_hash = bytes(32)

        def broken_tx_path(p):
            p.anchors[0].tx_path = [bytes(32)] * len(p.anchors[0].tx_path)

        def tampered_witness(p):
            p.witnesses[0].wit_data = key_b.get_pubkey().get_bytes()

        def wrong_out_type(p):
            p.claims[0].out_type = OUT_P2WSH

        def second_op_return(tx):
            tx.vout.insert(2, CTxOut(0, CScript([OP_RETURN, b"spare"])))

        self.log.info("rule:anchor-bounds - a payload with no anchor at all")
        self.expect_reject(bad, "Payload carries no anchors", payload_mutator=drop_anchors)

        self.log.info("rule:anchor-bounds - a transaction path longer than the bound")
        self.expect_reject(bad, "Anchor exceeds its length bounds", payload_mutator=long_path)

        self.log.info("rule:coverage - a claim naming an input outside the transaction")
        self.expect_reject(bad, "Claim names an input outside the transaction", payload_mutator=claim_outside)

        self.log.info("rule:coverage - two claims naming the same input")
        self.expect_reject(bad, "another claim already names", payload_mutator=claim_twice)

        self.log.info("rule:coverage - a hash-protected input that no claim names")
        self.expect_reject(bad, "no claim names it",
                           payload_mutator=lambda p: p.claims.pop())

        self.log.info("rule:payout - a self-salvaged record that still charges a fee")
        self.expect_reject(bad, "non-zero salvage fee", payload_mutator=paid_self_salvage)

        self.log.info("rule:opening - an anchor naming a block the node does not have")
        self.expect_reject(bad, "unknown or not on the active chain", payload_mutator=unknown_block)

        self.log.info("rule:opening - a transaction path that leads nowhere")
        self.expect_reject(bad, "does not lead to the block", payload_mutator=broken_tx_path)

        self.log.info("rule:binding - a witness that was never committed")
        self.expect_reject(bad, "doesn't have witness commit", payload_mutator=tampered_witness)

        self.log.info("rule:statement - a claim naming the wrong output type")
        self.expect_reject(bad, "does not reproduce the statement", payload_mutator=wrong_out_type)

        self.log.info("rule:pqsig - a signature with one byte flipped")
        self.expect_reject(bad, "SHRINCS", break_signature=True)

        self.log.info("rule:payload-output - a second OP_RETURN in the reveal")
        self.expect_reject(bad, "multi-op-return", tx_mutator=second_op_return)

        self.log.info("rule:opening - a commitment that is not yet buried deep enough")
        shallow = self.prepare("shallow", [[p2sh_script_input(REDEEM)]], [[0]])
        self.expect_reject(shallow, "not buried deep enough")

        def duplicate_record(p):
            p.witnesses.append(copy.deepcopy(p.witnesses[0]))
            p.claims[1].wit_idx = 1

        self.log.info("rule:binding - two records opening the same commitment")
        self.expect_reject(bad, "open the same commitment", payload_mutator=duplicate_record)

        self.log.info("rule:unused - an anchor that no witness record names")
        self.expect_reject(bad, "Anchor is named by no witness record",
                           payload_mutator=lambda p: p.anchors.append(copy.deepcopy(p.anchors[0])))

        self.log.info("rule:unused - a witness record that no claim names")
        self.expect_reject(bad, "Witness record is named by no claim",
                           payload_mutator=lambda p: p.witnesses.append(copy.deepcopy(p.witnesses[0])))

        self.log.info("--- the salvage payouts ---")

        def pay_elsewhere(tx):
            tx.vout[0].scriptPubKey = script_to_p2sh_script(REDEEM)

        def pay_short(tx):
            # Elements balances every asset exactly, so the satoshi taken from
            # the salvager has to reappear somewhere: give it to the rescuer.
            tx.vout[0].nValue.setToAmount(tx.vout[0].nValue.getAmount() - 1)
            tx.vout[-2].nValue.setToAmount(tx.vout[-2].nValue.getAmount() + 1)

        def payload_worth_something(tx):
            index = next(i for i, o in enumerate(tx.vout)
                         if bytes(o.scriptPubKey)[:1] == bytes([OP_RETURN]))
            tx.vout[index].nValue.setToAmount(1)
            tx.vout[-2].nValue.setToAmount(tx.vout[-2].nValue.getAmount() - 1)

        def push_payload_down(tx):
            tx.vout.insert(2, CTxOut(1000, P2SH_SPK))
            tx.vout[-2].nValue.setToAmount(tx.vout[-2].nValue.getAmount() - 1000)

        self.log.info("a payout that goes to some other script")
        self.expect_reject(salv_bad, "does not pay the script pubkey", tx_mutator=pay_elsewhere)

        self.log.info("a payout one satoshi short of what is owed")
        self.expect_reject(salv_bad, "pays less than the fee owed", tx_mutator=pay_short)

        self.log.info("a salvager entry that no witness record names")
        self.expect_reject(salv_bad, "named by no witness record",
                           payload_mutator=lambda p: p.salvagers.append(bytes(P2SH_SPK)))

        self.log.info("a witness record naming a salvager entry that is not there")
        self.expect_reject(salv_bad, "names a salvager entry outside the payload",
                           payload_mutator=lambda p: setattr(p.witnesses[0], "sv_idx", 9))

        self.log.info("the payload pushed past the position M' puts it at")

        self.expect_reject(salv_bad, "does not sit immediately after",
                           tx_mutator=push_payload_down, payload_index=3)

        self.log.info("--- what the anchor and the records must contain ---")

        pub_block = node.getrawtransaction(salv_bad["pub_txids"][0], True)["blockhash"]
        coinbase_anchor = self.build_anchor(node.getblock(pub_block)["tx"][0])

        self.log.info("an anchor whose transaction publishes no root at all")
        self.expect_reject(bad, "doesn't have any DropKick commits",
                           payload_mutator=lambda p: p.anchors.__setitem__(0, coinbase_anchor))

        self.log.info("a leaf index beyond the tree")
        self.expect_reject(bad, "leaf index is too long",
                           payload_mutator=lambda p: setattr(p.witnesses[0], "leaf_index", 65535))

        self.log.info("a witness whose length does not match its type")
        self.expect_reject(bad, "malformed for its type",
                           payload_mutator=lambda p: setattr(p.witnesses[0], "wit_data", bytes(20)))

        self.log.info("a 33-byte public key with the uncompressed prefix")
        self.expect_reject(bad, "malformed for its type",
                           payload_mutator=lambda p: setattr(p.witnesses[0], "wit_data",
                                                             b"\x04" + p.witnesses[0].wit_data[1:]))

        self.log.info("a payload output that is not worth zero")
        self.expect_reject(bad, "no well-formed DropKick payload", tx_mutator=payload_worth_something)

        self.log.info("salvage fees that overflow the money supply")
        self.expect_reject(salv_bad, "exceed the money supply",
                           late_payload_mutator=lambda p: setattr(p.witnesses[0], "sv_sat", MAX_MONEY + 1))

        self.log.info("--- payload limits ---")

        def repeat(field, times):
            return lambda p: setattr(p, field, getattr(p, field) * times)

        self.log.info("more anchors than the limit allows")
        self.expect_reject(bad, "Payload carries no anchors", payload_mutator=repeat("anchors", 17))

        self.log.info("more witness records than the limit allows")
        self.expect_reject(bad, "Payload carries no witness records",
                           payload_mutator=repeat("witnesses", 65))

        self.log.info("more claims than the limit allows")
        self.expect_reject(bad, "Payload carries no claims", payload_mutator=repeat("claims", 129))

        self.log.info("more salvager entries than the limit allows")
        self.expect_reject(bad, "more salvager entries than the limit",
                           payload_mutator=lambda p: setattr(p, "salvagers", [bytes(P2SH_SPK)] * 65))

        self.log.info("an unknown payload version")
        self.expect_reject(bad, "Unknown DropKick payload version",
                           payload_mutator=lambda p: setattr(p, "version", 2))

        self.log.info("--- the same rules hold for a block, not only the mempool ---")
        # Relay is only half the story: a miner can put a transaction straight
        # into a block, so ConnectBlock has to refuse it as well.
        broken = copy.deepcopy(bad["payload"])
        broken.claims[0].input_idx = 99
        tx = self.build_reveal(bad["rescues"], broken, bad["sk"], 1)
        assert_raises_rpc_error(-25, "Claim names an input outside the transaction",
                                self.generateblock, node, self.wallet.get_address(),
                                [tx.serialize().hex()])

        self.log.info("and a block carrying an unclaimed hash-protected input is invalid too")
        plain = self.p2sh_spend(pending[1])
        assert_raises_rpc_error(-25, UNCLAIMED, self.generateblock, node,
                                self.wallet.get_address(), [plain.serialize().hex()])

        self.log.info("--- the minimum fee ---")

        self.log.info("one satoshi under ceil(V * 1/1000) is refused")
        self.expect_reject(rich, "Fee doesn't satisfy", fee=required - 1)

        self.log.info("exactly ceil(V * 1/1000) is enough")
        self.reveal(rich, 1, fee=required)

        assert_equal(len(node.getrawmempool()), 0)


if __name__ == '__main__':
    DropKickTest(__file__).main()
