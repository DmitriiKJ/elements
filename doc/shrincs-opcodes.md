# SHRINCS Opcodes Specification

This document describes how to use the OP_SHRINCS (0xb3) and the OP_SHRINCSADD (0xb4) opcodes, which replace OP_NOP4 and OP_NOP5 respectively, and implement the [SHRINCS](https://github.com/SHRINCS/shrincs-bip) verification logic.

## Usage

Unlike ECDSA and Schnorr signatures which are small (less than 520 bytes) and can be pushed to the stack as a single element, SHRINCS has to be split into parts.

### Public keys

A SHRINCS public key is 48 bytes: `pk_seed || sl_root || sf_root`, so it is pushed with a 48-byte push (`0x30`).

### Signature structure

The topmost stack element `q` selects the layout and is the only element the interpreter interprets numerically. It is a minimally encoded `CScriptNum`:

| `q` | Meaning |
| :--- | :--- |
| `0` | Empty signature (see the Nullfail note below) |
| `1`…`255` | Stateful signature; `q` counts the Merkle path elements |
| `256` | Stateless signature |

Since a stateful Merkle path reaches `FXMSS_HEIGHT` = 255 elements, the stateless marker sits one above it. Note `q = 256` encodes as the two bytes `0x00 0x01`.

**Stateless signature stack layout:**

The signature is `indicator || R || FORS signature || hypertree signature` = 1 + 16 + 2240 + 3520 = 5777 bytes. The leading `indicator` byte is not pushed — the interpreter rederives it from `q` (see below). Neither the FORS nor the hypertree part fits in a single stack element, so both are split along their internal boundaries: one element per FORS tree, and two elements per hypertree layer.

| Position | Element | Size |
| :---: | :--- | :--- |
| `[-23]` | `R` | 16 bytes |
| `[-22..-13]` | `fors_part` (x10) | 224 bytes per part (one FORS tree) |
| `[-12..-3]` | `ht_part` (x10) | 352 bytes per part (half a hypertree layer) |
| `[-2]` | `sighash type` (optional) | 1 byte |
| `[-1]` | `q` | `256` |

Positions above assume the sighash byte is present; without it everything below `[-1]` shifts up by one.

So, in a script, the required push order is as follows: `<R> <fp1> ... <fp10> <hp1> ... <hp10> [<sighash_type>] <256>`

> [!IMPORTANT]
> **Block Signatures vs. SIGHASH Bytes**
> Standard UTXO transaction signatures append a 1-byte SIGHASH flag (e.g., `0x01` for `SIGHASH_ALL`) to the signature. However, **Block Signatures (Dynafed) DO NOT use a SIGHASH byte**.
>
> Block signatures additionally must always take the stateless path.

**Stateful signature stack layout:**

The signature is `indicator || R || leaf_index || grinding counter || WOTS+C chains || Merkle path`. As in the stateless case, the leading `indicator` byte is not pushed. The leaf's depth in the FXMSS tree equals the number of Merkle path elements, so `q` fully determines the signature length: 1 + 16 + `index_size` + 2 + 512 + 16·`q`, where `index_size = ceildiv(min(q, 64), 8)` is 1 to 8 bytes. That gives 548 bytes at `q = 1` up to 4619 bytes at `q = 255`.

| Position | Element | Size |
| :---: | :--- | :--- |
| `[-(5 + q)]` | `R` | 16 bytes |
| `[-(4 + q)]` | `leaf_index` | `index_size` bytes, big-endian |
| `[-(3 + q)]` | `wots` | 514 bytes (2-byte grinding counter + 512 bytes of chains) |
| `[-(2 + q)..-3]` | `merkle path` | 16 bytes per element |
| `[-2]` | `sighash type` (optional) | 1 byte |
| `[-1]` | `q` | 1–2 bytes |

Positions above assume the sighash byte is present; without it everything below `[-1]` shifts up by one.

Because `index_size` grows in whole bytes, the signature size does not grow uniformly with `q`: it is 660 bytes at `q = 8` and 677 bytes at `q = 9`, where the leaf index crosses into a second byte.

So, in a script, the required push order is as follows (example for `q = 3`): `<R> <leaf_index> <wots> <mp1> <mp2> <mp3> [<sighash_type>] <3>`

Note that `q` is derived from the signing leaf's position, not from the number of signatures the key has issued: a leaf at height `h` in the FXMSS tree gives `q = FXMSS_HEIGHT - h`. In a balanced tree every leaf sits at the same height, so `q` is constant for the life of the key and the state counter shows up in `leaf_index` instead. In an unbalanced tree the leaf descends one level per signature, so `q` grows by one each time and `leaf_index` stays 1 — except for the very last signature, which reuses the same `q` as the one before it with `leaf_index` 0.

### The indicator byte

`q` and the `indicator` byte carry the same information: `q = FXMSS_HEIGHT - indicator`, and for a stateless signature `indicator` is `FXMSS_HEIGHT` while `q` is `FXMSS_HEIGHT + 1`. They serve different consumers. The interpreter needs `q` on top of the stack to know how many elements to pop before it can look at any signature bytes, while `indicator` is part of the signature proper, so that the signature handed to the verifier is byte-identical to a SHRINCS signature as the specification serializes it.

Because the two are redundant, `indicator` is **not** pushed on the stack. The interpreter pops `q`, derives `indicator` from it, and prepends that byte to the signature it reassembles from the remaining elements. This keeps a signer from pushing a `q` and an `indicator` that disagree, and saves a stack element.

### Opcodes

**OP_SHRINCS (Single Signature)**
Behaves similarly to the legacy `OP_CHECKSIG`. The script structure is:
```text
<sig_components> <pubkey> OP_SHRINCS
```

**OP_SHRINCSADD**
Behaves similarly to the `OP_CHECKSIGADD`. This example represent 2-of-3 threshold signature (where the third signer did not provide a signature, hence the `OP_0`):
```text
<OP_0> <sig2_components> <sig1_components> <pubkey1> OP_SHRINCS <pubkey2> OP_SHRINCSADD <pubkey3> OP_SHRINCSADD OP_2 OP_NUMEQUAL
```

> **Note:** Due to the **Nullfail** rule, the only way for `OP_SHRINCS` to return `False`, and for `OP_SHRINCSADD` to leave the counter unchanged, is if an empty signature (OP_0) is provided. Any other invalid signature will cause the entire script to fail.
