"""DropKick transaction building for the sandbox.

Deliberately a copy of the helpers in test/functional/feature_dropkick.py
rather than a shared module, so the test and the sandbox evolve independently.
The payload format itself comes from test_framework/dropkick.py.
"""

import os
import sys
from io import BytesIO

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "test", "functional"))

from test_framework.crypto import shrincs  # noqa: E402
from test_framework.crypto.bip32 import ExtKey  # noqa: E402
from test_framework.dropkick import (  # noqa: E402
    COMMITMENT_DEPTH,
    FEE_RATIO_DEN,
    FEE_RATIO_NUM,
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
from test_framework.key import ECKey  # noqa: E402
from test_framework.messages import (  # noqa: E402
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    CTxOutValue,
    deser_compact_size,
    deser_string,
    hash256,
    ser_string,
)
from test_framework.script import (  # noqa: E402
    CScript,
    OP_0,
    OP_DROP,
    OP_RETURN,
    OP_TRUE,
    hash160,
    sign_input_legacy,
    sign_input_segwitv0,
)
from test_framework.script_util import (  # noqa: E402
    key_to_p2pkh_script,
    key_to_p2sh_p2wpkh_script,
    key_to_p2wpkh_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)

REVEAL_FEE = 40000
SPEND_FEE = 1000
SF_SHAPE_UNBALANCED = 0x00

OUT_KINDS = {
    "p2pkh": OUT_P2PKH,
    "p2wpkh": OUT_P2WPKH,
    "p2sh_p2wpkh": OUT_P2SH_P2WPKH,
    "p2sh": OUT_P2SH,
    "p2wsh": OUT_P2WSH,
}
KEY_KINDS = ("p2pkh", "p2wpkh", "p2sh_p2wpkh")
SCRIPT_KINDS = ("p2sh", "p2wsh")


def eckey(secret, compressed=True):
    key = ECKey()
    key.set(secret, compressed)
    return key


def new_eckey(compressed=True):
    key = ECKey()
    key.generate(compressed)
    return key


def new_unique_script():
    """A script that needs no signature, made unique so each has its own statement."""
    return CScript([os.urandom(8), OP_DROP, OP_TRUE])


def decode_tx(raw_hex):
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(raw_hex)))
    return tx


def witness_stripped(raw_hex):
    return decode_tx(raw_hex).serialize_without_witness()


# --- payload parsing ---------------------------------------------------------

def _read(f, n):
    data = f.read(n)
    if len(data) != n:
        raise ValueError("payload ends early")
    return data


def parse_payload(data):
    """Inverse of DropKickPayload.serialize; raises ValueError on malformed input."""
    f = BytesIO(data)
    p = DropKickPayload()
    p.version = _read(f, 1)[0]
    p.pk_pq = _read(f, 48)
    p.anchors = []
    for _ in range(deser_compact_size(f)):
        a = DropKickAnchor(block_hash=_read(f, 32), tx_index=deser_compact_size(f))
        a.tx_path = [_read(f, 32) for _ in range(deser_compact_size(f))]
        a.tx_data = deser_string(f)
        p.anchors.append(a)
    p.salvagers = [deser_string(f) for _ in range(deser_compact_size(f))]
    p.witnesses = []
    for _ in range(deser_compact_size(f)):
        w = DropKickWitness(anchor_idx=deser_compact_size(f), sv_idx=deser_compact_size(f))
        w.sv_sat = int.from_bytes(_read(f, 8), "little")
        w.leaf_index = int.from_bytes(_read(f, 2), "little")
        w.agg_path = [_read(f, 32) for _ in range(14)]
        w.wit_type = _read(f, 1)[0]
        w.wit_data = deser_string(f)
        p.witnesses.append(w)
    p.claims = []
    for _ in range(deser_compact_size(f)):
        c = DropKickClaim(input_idx=deser_compact_size(f), wit_idx=deser_compact_size(f))
        c.out_type = _read(f, 1)[0]
        c.path = [int.from_bytes(_read(f, 4), "little") for _ in range(deser_compact_size(f))]
        p.claims.append(c)
    p.sig = deser_string(f)
    if f.read(1):
        raise ValueError("trailing bytes after the payload")
    return p


def payload_from_spk(spk):
    """The payload an OP_RETURN output carries, or None if it carries none."""
    script = CScript(bytes(spk))
    if not bytes(script)[:1] == bytes([OP_RETURN]):
        return None
    try:
        ops = list(script)
        if len(ops) != 2 or not isinstance(ops[1], bytes):
            return None
        return parse_payload(ops[1])
    except Exception:
        return None


def verify_reveal(tx, payload_index, payload):
    """Recompute the sighash of rule:signing-form and check the SHRINCS signature."""
    sighash = dropkick_sighash(tx, payload_index, payload)
    return sighash, shrincs.shrincs_verify(sighash, payload.sig, b"", payload.pk_pq)


# --- inputs ----------------------------------------------------------------
#
# An input spec is what both the ordinary spend and the reveal need from a
# locked output: its script pubkey, the DropKick witness and type codes, and
# how to fill in and sign the legacy satisfaction.

def _key_input(kind, key):
    pub = key.get_pubkey().get_bytes()
    if kind == "p2pkh":
        return {
            "spk": key_to_p2pkh_script(pub),
            "witness": pub,
            "prepare": lambda tx, i: setattr(tx.vin[i], "scriptSig", CScript([pub])),
            "sign": lambda tx, i, amount: sign_input_legacy(tx, i, key_to_p2pkh_script(pub), key),
        }
    if kind == "p2wpkh":
        def prepare(tx, i):
            tx.wit.vtxinwit[i].scriptWitness.stack = [pub]
        return {
            "spk": key_to_p2wpkh_script(pub),
            "witness": pub,
            "prepare": prepare,
            "sign": lambda tx, i, amount: sign_input_segwitv0(tx, i, key_to_p2pkh_script(pub), amount, key),
        }
    if kind == "p2sh_p2wpkh":
        redeem = CScript([OP_0, hash160(pub)])

        def prepare(tx, i):
            tx.vin[i].scriptSig = CScript([bytes(redeem)])
            tx.wit.vtxinwit[i].scriptWitness.stack = [pub]
        return {
            "spk": key_to_p2sh_p2wpkh_script(pub),
            "witness": pub,
            "prepare": prepare,
            "sign": lambda tx, i, amount: sign_input_segwitv0(tx, i, key_to_p2pkh_script(pub), amount, key),
        }
    raise ValueError(f"not a key output type: {kind}")


def _script_input(kind, script):
    if kind == "p2sh":
        return {
            "spk": script_to_p2sh_script(script),
            "witness": ser_string(script),
            "prepare": lambda tx, i: setattr(tx.vin[i], "scriptSig", CScript([bytes(script)])),
            "sign": lambda tx, i, amount: None,
        }
    if kind == "p2wsh":
        def prepare(tx, i):
            tx.wit.vtxinwit[i].scriptWitness.stack = [bytes(script)]
        return {
            "spk": script_to_p2wsh_script(script),
            "witness": ser_string(script),
            "prepare": prepare,
            "sign": lambda tx, i, amount: None,
        }
    raise ValueError(f"not a script output type: {kind}")


def input_spec(utxo, xprv_seed):
    """Rebuild the input spec of a stored output from its key material."""
    kind, key = utxo["kind"], utxo["key"]
    if key["type"] == "ec":
        spec = _key_input(kind, eckey(bytes.fromhex(key["secret"]), key["compressed"]))
        spec.update(wit_type=WIT_PUBKEY, path=[])
    elif key["type"] == "xprv":
        master = ExtKey.from_seed(bytes.fromhex(xprv_seed))
        child = master.derive_path(key["path"])
        spec = _key_input(kind, eckey(child.secret))
        spec.update(witness=master.serialize(), wit_type=WIT_XPRV, path=list(key["path"]))
    elif key["type"] == "script":
        spec = _script_input(kind, CScript(bytes.fromhex(key["script"])))
        spec.update(wit_type=WIT_SCRIPT, path=[])
    else:
        raise ValueError(f"unknown key type: {key['type']}")
    spec["out_type"] = OUT_KINDS[kind]
    return spec


def outpoint(utxo):
    return COutPoint(int(utxo["txid"], 16), utxo["vout"])


# --- ordinary spend --------------------------------------------------------

def build_plain_spend(utxo, spec, dest_spk, fee=SPEND_FEE):
    """Spend one output the pre-DropKick way: legacy satisfaction, no payload."""
    tx = CTransaction()
    tx.vin.append(CTxIn(outpoint(utxo), b""))
    tx.wit.vtxinwit.append(CTxInWitness())
    spec["prepare"](tx, 0)
    tx.vout.append(CTxOut(utxo["amount"] - fee, CScript(dest_spk)))
    tx.vout.append(CTxOut(fee))
    spec["sign"](tx, 0, CTxOutValue(utxo["amount"]))
    tx.rehash()
    return tx


# --- commitment side -------------------------------------------------------

def build_anchor(rpc, txid):
    block_hash = rpc.getrawtransaction(txid, True)["blockhash"]
    block = rpc.getblock(block_hash)

    txids = [bytes.fromhex(t)[::-1] for t in block["tx"]]
    index = block["tx"].index(txid)

    path, layer, pos = [], txids, index
    while len(layer) > 1:
        if len(layer) % 2:
            layer = layer + [layer[-1]]
        path.append(layer[pos ^ 1])
        layer = [hash256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        pos >>= 1
    if layer[0] != bytes.fromhex(block["merkleroot"])[::-1]:
        raise RuntimeError("block merkle path does not reproduce the header's root")

    return DropKickAnchor(
        block_hash=bytes.fromhex(block_hash)[::-1],
        tx_index=index,
        tx_path=path,
        tx_data=witness_stripped(rpc.getrawtransaction(txid)),
    )


# --- reveal side -----------------------------------------------------------

def required_fee(value):
    return (value * FEE_RATIO_NUM + FEE_RATIO_DEN - 1) // FEE_RATIO_DEN


def build_reveal(rescues, payload, sk, state_ctr, fee, dest_spk):
    """Assemble, sign and return a reveal, in the order of rem:signing-order."""
    tx = CTransaction()
    for op, _, _ in rescues:
        tx.vin.append(CTxIn(op, b""))
        tx.wit.vtxinwit.append(CTxInWitness())
    for i, (_, spec, _) in enumerate(rescues):
        spec["prepare"](tx, i)

    total = sum(amount for _, _, amount in rescues)

    owed = [0] * len(payload.salvagers)
    for w in payload.witnesses:
        if w.sv_idx:
            owed[w.sv_idx - 1] += w.sv_sat
    paid = 0
    for k, amount_owed in enumerate(owed):
        if amount_owed == 0:
            continue
        tx.vout.append(CTxOut(amount_owed, CScript(payload.salvagers[k])))
        paid += amount_owed

    change = total - fee - paid
    if change <= 0:
        raise ValueError(f"rescued value {total} does not cover fee {fee} and salvage payouts {paid}")

    payload_index = len(tx.vout)
    tx.vout.append(CTxOut(0, payload.output_script()))
    tx.vout.append(CTxOut(change, CScript(dest_spk)))
    tx.vout.append(CTxOut(fee))

    sighash = dropkick_sighash(tx, payload_index, payload)
    sig = shrincs.shrincs_sign(sighash, b"", sk, state_ctr, None)
    if sig is None:
        raise RuntimeError("SHRINCS signing failed")
    payload.sig = sig
    tx.vout[payload_index].scriptPubKey = payload.output_script()

    for i, (_, spec, amount) in enumerate(rescues):
        spec["sign"](tx, i, CTxOutValue(amount))
    tx.rehash()
    return tx, sighash, payload_index


__all__ = [
    "COMMITMENT_DEPTH", "DropKickClaim", "DropKickPayload", "DropKickWitness",
    "ExtKey", "KEY_KINDS", "OUT_KINDS", "REVEAL_FEE", "SCRIPT_KINDS", "SF_SHAPE_UNBALANCED",
    "build_agg_tree", "build_anchor", "build_plain_spend", "build_reveal", "commitment",
    "decode_tx", "input_spec", "make_publication_script", "new_eckey", "new_unique_script",
    "outpoint", "payload_from_spk", "required_fee", "shrincs", "verify_reveal",
]
