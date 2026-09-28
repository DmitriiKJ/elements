#!/usr/bin/env python3
# Copyright (c) 2026 The Elements developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A small BIP32 implementation for the functional tests.

Only what a test needs: derive a private child, hand out the public key, and
serialise the extended key the way BIP32 defines it. There is no base58, no
extended public key and no path parsing.

Note the two lengths that go with a serialised extended key. BIP32 defines 78
bytes, the first four of which are the network version. Bitcoin Core's CExtKey
stores and decodes only the 74-byte body; whoever hands it these bytes has to
skip the version itself.
"""

import hashlib
import hmac
import struct

from .ripemd160 import ripemd160
from . import secp256k1

BIP32_EXTKEY_SIZE = 74                 #: what CExtKey::Decode expects
BIP32_EXTKEY_WITH_VERSION_SIZE = 78    #: what BIP32 defines

HARDENED = 0x80000000

# Version bytes. They identify the network and are not otherwise interpreted;
# DropKick hashes them along with the rest of the witness, so whichever is used
# to commit has to be used to reveal.
VERSION_MAIN_PRIVATE = bytes.fromhex("0488ADE4")
VERSION_TEST_PRIVATE = bytes.fromhex("04358394")


def _hash160(data):
    return ripemd160(hashlib.sha256(data).digest())


def _pubkey_bytes(secret):
    """The compressed public key of a 32-byte secret."""
    point = int.from_bytes(secret, "big") * secp256k1.G
    return point.to_bytes_compressed()


class ExtKey:
    """An extended private key: a secret plus the chain code that extends it."""

    def __init__(self, secret, chaincode, depth=0, fingerprint=b"\x00" * 4, child_num=0):
        assert len(secret) == 32 and len(chaincode) == 32
        self.secret = secret
        self.chaincode = chaincode
        self.depth = depth
        self.fingerprint = fingerprint
        self.child_num = child_num

    @classmethod
    def from_seed(cls, seed):
        digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        return cls(secret=digest[:32], chaincode=digest[32:])

    def pubkey(self):
        """The 33-byte compressed public key."""
        return _pubkey_bytes(self.secret)

    def derive(self, index):
        """One BIP32 step. An index at or above 2**31 is hardened."""
        if index >= HARDENED:
            # A hardened step needs the private key, which is why a reveal of
            # wit_type 0x02 cannot carry an extended *public* key.
            data = b"\x00" + self.secret + struct.pack(">I", index)
        else:
            data = self.pubkey() + struct.pack(">I", index)

        digest = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        tweak = int.from_bytes(digest[:32], "big")
        assert tweak < secp256k1.GE.ORDER, "invalid child; a real wallet would skip this index"

        child = (tweak + int.from_bytes(self.secret, "big")) % secp256k1.GE.ORDER
        assert child != 0, "invalid child; a real wallet would skip this index"

        return ExtKey(
            secret=child.to_bytes(32, "big"),
            chaincode=digest[32:],
            depth=self.depth + 1,
            fingerprint=_hash160(self.pubkey())[:4],
            child_num=index,
        )

    def derive_path(self, path):
        """Walk a list of child numbers, hardened ones already offset."""
        key = self
        for index in path:
            key = key.derive(index)
        return key

    def serialize_body(self):
        """The 74 bytes CExtKey stores: everything but the version."""
        return (struct.pack("B", self.depth)
                + self.fingerprint
                + struct.pack(">I", self.child_num)
                + self.chaincode
                + b"\x00"
                + self.secret)

    def serialize(self, version=VERSION_MAIN_PRIVATE):
        """The 78 bytes BIP32 defines, which is what a witness record carries."""
        out = version + self.serialize_body()
        assert len(out) == BIP32_EXTKEY_WITH_VERSION_SIZE
        return out
