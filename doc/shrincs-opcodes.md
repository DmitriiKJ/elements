# SHRINCS Opcodes Specification

This document describes how to use the OP_SHRINCS (0xb3) and the OP_SHRINCSADD (0xb4) opcodes, which replace OP_NOP4 and OP_NOP5 respectively, and implement the [SHRINCS](https://github.com/SHRINCS/shrincs-bip) verification logic.

## Usage

Unlike ECDSA and Schnorr signatures which are small (less than 520 bytes) and can be pushed to the stack as a single element, SHRINCS has to be split into parts.

This document follows the layout fixed by the ELIP for `OP_SHRINCS` and `OP_SHRINCSADD`.

### Public keys

A SHRINCS public key is 48 bytes: `pk_seed || sl_root || sf_root`, so it is pushed with a 48-byte push (`0x30`). An element of any other length fails the script with `SCRIPT_ERR_PUBKEYTYPE`, before the signature below it is parsed.

### Signature structure

The topmost stack element `q` selects the layout and is the only element the interpreter interprets numerically. Its encoding must be minimal and at most 2 bytes **whatever script verification flags are set**; any other encoding fails the script with `SCRIPT_ERR_MINIMALDATA`. It is read as a `CScriptNum`:

| `q` | Meaning |
| :--- | :--- |
| `0` | Empty signature (see the Nullfail note below) |
| `1`…`255` | Stateful signature; `q` counts the Merkle path elements |
| `256` | Stateless signature |

Since a stateful Merkle path reaches `FXMSS_HEIGHT` = 255 elements, the stateless marker sits one above it. Note `q = 256` encodes as the two bytes `0x00 0x01`.

**How the signature is split:**

The signature is cut into parts of **80 bytes**, the last part carrying whatever remains. The cut points follow nothing in the structure of the signature: a part may begin in the middle of a Merkle path node and end in the middle of the next. The interpreter concatenates the parts back into one byte string before it parses anything.

Two separate limits set that size. `MAX_SCRIPT_ELEMENT_SIZE` = 520 is the consensus limit that makes a split necessary at all, but relay policy caps a standard witness element at 80 bytes on both witness spending paths (`MAX_STANDARD_P2WSH_STACK_ITEM_SIZE` and `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE`), so a signature split only to the consensus limit is valid but non-relayable. Cutting at 80 satisfies both at once.

Both the number of parts and every individual length follow from `q` alone:

```text
 L = 530 + index_size + 16 * q     stateful, index_size = ceildiv(min(q, 64), 8)
 L = SPHX_SIGNATURE_SIZE = 5776    stateless
 N = ceildiv(L, 80)
```

where `L` is the length of the signature as the SHRINCS specification serializes it, less its leading indicator byte. The first `N - 1` parts are exactly 80 bytes and the last is `L - 80 * (N - 1)`, between 1 and 80. Any other length fails the script with `SCRIPT_ERR_SHRINCS_SIG_SIZE`.

**Stack layout:**

The layout is the same for both signature types; only `L`, and with it `N`, differ. From top to bottom:

| Position | Element | Size |
| :---: | :--- | :--- |
| `[-1]` | `q` | 1–2 bytes |
| `[-2]` | `sighash type` (optional) | 1 byte |
| `[-(2 + N)..-3]` | `part_1 .. part_N` | 80 bytes each, except `part_N` |

Positions above assume the sighash byte is present; without it everything below `[-1]` shifts up by one. The parts are pushed in index order, so `part_1` sits deepest and `part_N` carries the remainder.

| Signature | `L` | `N` | Last part | Stack elements |
| :--- | ---: | ---: | ---: | ---: |
| Stateful, `q = 1` | 547 | 7 | 67 bytes | 9 |
| Stateful, `q = 255` | 4618 | 58 | 58 bytes | 60 |
| Stateless | 5776 | 73 | 16 bytes | 75 |

The element count includes `q` and the SIGHASH byte; a block signature carries no SIGHASH byte and occupies one fewer.

So, in a script, the required push order is: `<part_1> ... <part_N> [<sighash_type>] <q>`

> [!IMPORTANT]
> **Block Signatures vs. SIGHASH Bytes**
> Standard UTXO transaction signatures carry a 1-byte SIGHASH flag (e.g., `0x01` for `SIGHASH_ALL`) as a stack element of its own, just below `q`. However, **Block Signatures (Dynafed) DO NOT use a SIGHASH byte**.
>
> Block signatures additionally must always take the stateless path.

**What the parts concatenate back into:**

The parts concatenated bottom to top are the SHRINCS signature exactly as the specification serializes it, less the leading indicator byte.

For a stateful signature that byte string is `R || leaf_index || wots+c || mp_1 .. mp_q`: the 16-byte randomizer, the big-endian `leaf_index` of `index_size` = `ceildiv(min(q, 64), 8)` bytes, a 2-byte grinding counter followed by 512 bytes of WOTS+C chain values, and the 16-byte Merkle path nodes. That is 548 bytes at `q = 1` up to 4619 bytes at `q = 255`, indicator included.

For a stateless signature it is `R || FORS signature || hypertree signature` = 16 + 2240 + 3520 = 5776 bytes, which together with the indicator is 5777.

None of those boundaries is visible in the stack layout.

Because `index_size` grows in whole bytes, the signature size does not grow uniformly with `q`: it is 660 bytes at `q = 8` and 677 bytes at `q = 9`, where the leaf index crosses into a second byte. `N` in turn increases only where `L` crosses a multiple of 80.

Note that `q` is derived from the signing leaf's position, not from the number of signatures the key has issued: a leaf at height `h` in the FXMSS tree gives `q = FXMSS_HEIGHT - h`. In a balanced tree every leaf sits at the same height, so `q` is constant for the life of the key and the state counter shows up in `leaf_index` instead. In an unbalanced tree the leaf descends one level per signature, so `q` grows by one each time and `leaf_index` stays 1 — except for the very last signature, which reuses the same `q` as the one before it with `leaf_index` 0.

### The SIGHASH byte

In transaction context a 1-byte SIGHASH flag sits on the stack immediately below `q`, and it is a stack element of its own rather than a suffix on the signature. An element that is not exactly one byte, or whose value is not a defined hashtype, fails the script with `SCRIPT_ERR_SCHNORR_SIG_HASHTYPE`.

Which context applies is determined by the signature checker, not by a script verification flag: transaction validation uses a checker that computes a sighash over the spending transaction and consumes the byte, while block validation uses one whose message is the block hash and which consumes no SIGHASH byte.

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
