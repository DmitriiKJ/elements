# SHRINCS Opcodes Specification

This document describes how to use the OP_SHRINCS (0xb3) and the OP_SHRINCSADD (0xb4) opcodes, which replace OP_NOP4 and OP_NOP5 respectively, and implement the [SHRINCS](https://github.com/BlockstreamResearch/shrincs-specification) verification logic.

## Usage

Unlike ECDSA and Schnorr signatures which are small (less than 520 bytes) and can be pushed to the stack as a single element, SHRINCS has to be split into parts.

### Signature structure

**Stateless signature stack layout:**

| Position | Element | Size |
| :---: | :--- | :--- |
| `[-10]` | `sf part` | 16 bytes |
| `[-9]` | `pors_R` | 32 bytes |
| `[-8..-5]` | `pors_part` (x4) | 388 bytes per part |
| `[-4..-3]` | `xmss_layer` (x2) | 484 bytes per layer |
| `[-2]` | `sighash type` (optional) | 1 byte |
| `[-1]` | `q` | 1 byte (stateless signatures always require q = 0xff) |

> [!IMPORTANT]
> **Block Signatures vs. SIGHASH Bytes**
> Standard UTXO transaction signatures append a 1-byte SIGHASH flag (e.g., `0x01` for `SIGHASH_ALL`) to the signature. However, **Block Signatures (Dynafed) DO NOT use a SIGHASH byte**.
> 

So, in a script, the required push order is as follows: `<sf> <R> <pp1> <pp2> <pp3> <pp4> <xmssl1> <xmssl2> [<sighash_type>] <0xff>`

**Stateful signature stack layout:**

State (q) from 1 to 142 means leaf in a uxmss tree, so for q = 142 merkle path consists of 141 leaves, otherwise q represents the number of Merkle path leaves (mpl).

| Position | Element | Size |
| :---: | :--- | :--- |
| `[-(4 + mpl)]` | `sl part` | 16 bytes |
| `[-(3 + mpl)]` | `wots` | 292 bytes |
| `[-(2 + mpl)..-3]` | `merkle path` | 16 bytes per leaf |
| `[-2]` | `sighash type` | 1 byte |
| `[-1]` | `q` | 1 byte |

So, in a script, the required push order is as follows (example for `q = 3`): `<sl> <wots> <mp1> <mp2> <mp3> <sighash_type> <q>`

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