#!/usr/bin/env python3
# Copyright (c) 2026 The Elements developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""DropKick commit/reveal helpers for the functional tests.

This is a second, independent implementation of the payload format that
src/dropkick/ validates.
"""

import copy
import struct

from .key import TaggedHash
from .messages import (
    hash256,
    ser_compact_size,
    ser_string,
)
from .script import CScript, OP_RETURN

# --- parameters (sec:parameters) ---

COMMITMENT_DEPTH = 1440
FEE_RATIO_NUM = 1
FEE_RATIO_DEN = 1000

# --- aggregation tree (con:tree) ---

AGG_TREE_HEIGHT = 14
AGG_TREE_LEAVES = 1 << AGG_TREE_HEIGHT

# --- publication (sec:publication) ---

DKCK_MAGIC = b"DKCK"
PUBLICATION_PUSH_SIZE = 36
PUBLICATION_SCRIPT_SIZE = 38

# --- witness and output type codes (sec:ka) ---

WIT_PUBKEY = 0x01
WIT_XPRV = 0x02
WIT_SCRIPT = 0x03

OUT_P2PKH = 0x01
OUT_P2WPKH = 0x02
OUT_P2SH_P2WPKH = 0x03
OUT_P2SH = 0x04
OUT_P2WSH = 0x05


# --------------------------------------------------------------------------
# tagged hashes (sec:hashes)
# --------------------------------------------------------------------------

def dk_commit(data):
    return TaggedHash("DropKick/commit", data)


def dk_inner(data):
    return TaggedHash("DropKick/inner", data)


def dk_leaf(data):
    return TaggedHash("DropKick/leaf", data)


def dk_branch(data):
    return TaggedHash("DropKick/branch", data)


def dk_sighash(data):
    return TaggedHash("DropKick/sighash", data)


# --------------------------------------------------------------------------
# merkle walks
# --------------------------------------------------------------------------

def agg_leaf_hash(commitment):
    """leaf_i = H_leaf(C_i)"""
    assert len(commitment) == 32
    return dk_leaf(commitment)


def agg_branch_hash(left, right):
    """branch(x, y) = H_branch(x || y), left child first"""
    assert len(left) == 32 and len(right) == 32
    return dk_branch(left + right)


def agg_root_from_path(leaf, path, leaf_index):
    """Walk a leaf up the aggregation tree.

    Bit l of leaf_index gives the side of the sibling at level l, so the proof
    carries neither a depth field nor direction bits.
    """
    assert len(path) == AGG_TREE_HEIGHT, "aggregation path must be exactly 14 siblings"
    assert 0 <= leaf_index < AGG_TREE_LEAVES
    node = leaf
    for level in range(AGG_TREE_HEIGHT):
        sibling = path[level]
        if (leaf_index >> level) & 1 == 0:
            node = agg_branch_hash(node, sibling)
        else:
            node = agg_branch_hash(sibling, node)
    return node


def build_agg_tree(commitments):
    """Build a full-height tree and return (root, [path per commitment]).

    Leaves hold the commitments in order; every remaining leaf repeats the last
    one, so a batch of any size still produces a tree of fixed height.
    """
    assert 1 <= len(commitments) <= AGG_TREE_LEAVES
    leaves = [agg_leaf_hash(c) for c in commitments]
    leaves += [leaves[-1]] * (AGG_TREE_LEAVES - len(leaves))

    # Keep every level so that paths can be read off afterwards.
    levels = [leaves]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        levels.append([agg_branch_hash(cur[i], cur[i + 1]) for i in range(0, len(cur), 2)])

    root = levels[-1][0]
    paths = []
    for index in range(len(commitments)):
        path, pos = [], index
        for level in range(AGG_TREE_HEIGHT):
            path.append(levels[level][pos ^ 1])
            pos >>= 1
        paths.append(path)
    return root, paths


def block_merkle_root_from_path(txid, path, tx_index):
    """Walk a txid up the block transaction tree: double SHA256, left first."""
    assert tx_index < (1 << len(path))
    node = txid
    for level, sibling in enumerate(path):
        if (tx_index >> level) & 1 == 0:
            node = hash256(node + sibling)
        else:
            node = hash256(sibling + node)
    return node


def tx_data_hash(tx_data):
    """The txid of the transaction an anchor carries."""
    return hash256(tx_data)


# --------------------------------------------------------------------------
# publication (sec:publication)
# --------------------------------------------------------------------------

def make_publication_script(root):
    """OP_RETURN OP_PUSHBYTES_36 <magic> <root>, 38 bytes in total."""
    assert len(root) == 32
    return CScript([OP_RETURN, DKCK_MAGIC + root])


def parse_publication_script(spk):
    """Return the root a published output carries, or None."""
    spk = bytes(spk)
    if len(spk) != PUBLICATION_SCRIPT_SIZE:
        return None
    if spk[0] != OP_RETURN or spk[1] != PUBLICATION_PUSH_SIZE:
        return None
    if spk[2:6] != DKCK_MAGIC:
        return None
    return spk[6:38]


# --------------------------------------------------------------------------
# commitment (con:commitment)
# --------------------------------------------------------------------------

def opening_message(pk_pq, spk, sv_sat):
    """c_message = pk_pq || len(spk) || spk || sv_sat

    The script pubkey enters with its length prefix, so a self-salvaged
    commitment contributes a single zero byte where an empty string would be.
    """
    assert len(pk_pq) == 48, "pk_pq is the 48-byte SHRINCS public key"
    return pk_pq + ser_string(spk) + struct.pack("<Q", sv_sat)


def commitment(witness, pk_pq, spk, sv_sat):
    """C = H_commit(H_inner(w || c_message) || c_message)"""
    cmsg = opening_message(pk_pq, spk, sv_sat)
    return dk_commit(dk_inner(witness + cmsg) + cmsg)


# --------------------------------------------------------------------------
# payload serialisation (sec:payload)
# --------------------------------------------------------------------------

def _ser_hash_vector(hashes):
    out = ser_compact_size(len(hashes))
    for h in hashes:
        assert len(h) == 32
        out += h
    return out


class DropKickAnchor:
    def __init__(self, block_hash=b"\x00" * 32, tx_index=0, tx_path=None, tx_data=b""):
        self.block_hash = block_hash
        self.tx_index = tx_index
        self.tx_path = tx_path if tx_path is not None else []
        self.tx_data = tx_data

    def serialize(self):
        return (self.block_hash
                + ser_compact_size(self.tx_index)
                + _ser_hash_vector(self.tx_path)
                + ser_string(self.tx_data))


class DropKickWitness:
    def __init__(self, anchor_idx=0, sv_idx=0, sv_sat=0, leaf_index=0,
                 agg_path=None, wit_type=WIT_PUBKEY, wit_data=b""):
        self.anchor_idx = anchor_idx
        self.sv_idx = sv_idx
        self.sv_sat = sv_sat
        self.leaf_index = leaf_index
        self.agg_path = agg_path if agg_path is not None else []
        self.wit_type = wit_type
        self.wit_data = wit_data

    def serialize(self):
        assert len(self.agg_path) == AGG_TREE_HEIGHT
        out = ser_compact_size(self.anchor_idx)
        out += ser_compact_size(self.sv_idx)
        out += struct.pack("<Q", self.sv_sat)
        out += struct.pack("<H", self.leaf_index)
        for h in self.agg_path:          # fixed 14 siblings, no length prefix
            assert len(h) == 32
            out += h
        out += struct.pack("<B", self.wit_type)
        out += ser_string(self.wit_data)
        return out


class DropKickClaim:
    def __init__(self, input_idx=0, wit_idx=0, out_type=OUT_P2PKH, path=None):
        self.input_idx = input_idx
        self.wit_idx = wit_idx
        self.out_type = out_type
        self.path = path if path is not None else []

    def serialize(self):
        out = ser_compact_size(self.input_idx)
        out += ser_compact_size(self.wit_idx)
        out += struct.pack("<B", self.out_type)
        out += ser_compact_size(len(self.path))
        for step in self.path:
            out += struct.pack("<I", step)
        return out


class DropKickPayload:
    def __init__(self):
        self.version = 1
        self.pk_pq = b"\x00" * 48
        self.anchors = []
        self.salvagers = []
        self.witnesses = []
        self.claims = []
        self.sig = b""

    def serialize(self):
        assert len(self.pk_pq) == 48
        out = struct.pack("<B", self.version)
        out += self.pk_pq                       # 48 raw bytes, no prefix
        out += ser_compact_size(len(self.anchors))
        for a in self.anchors:
            out += a.serialize()
        out += ser_compact_size(len(self.salvagers))
        for spk in self.salvagers:
            out += ser_string(spk)
        out += ser_compact_size(len(self.witnesses))
        for w in self.witnesses:
            out += w.serialize()
        out += ser_compact_size(len(self.claims))
        for c in self.claims:
            out += c.serialize()
        out += ser_string(self.sig)
        return out

    def output_script(self):
        """The scriptPubKey of the output that carries this payload."""
        return CScript([OP_RETURN, self.serialize()])

    def blanked_output_script(self):
        """The same output with sig_len set to zero and sig omitted.

        Removing the signature shortens the payload, so the push opcode and the
        script's own length prefix are recomputed rather than carried over.
        """
        saved, self.sig = self.sig, b""
        try:
            return CScript([OP_RETURN, self.serialize()])
        finally:
            self.sig = saved


# --------------------------------------------------------------------------
# the signed message (sec:sighash)
# --------------------------------------------------------------------------

def signing_form(tx, payload_index, payload):
    """tx* per rule:signing-form: blank every scriptSig, blank the payload."""
    star = copy.deepcopy(tx)
    for txin in star.vin:
        txin.scriptSig = b""
    star.vout[payload_index].scriptPubKey = payload.blanked_output_script()
    return star


def dropkick_sighash(tx, payload_index, payload):
    """sighash = H_sighash(ser(tx*)), serialised without witness data."""
    star = signing_form(tx, payload_index, payload)
    return dk_sighash(star.serialize_without_witness())
