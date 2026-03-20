# SHRINCS Opcodes Specification

This document describes how to use the OP_SHRINCS (0xb3) and the OP_MULTISHRINCS (0xb4) opcodes, which replace OP_NOP4 and OP_NOP5 respectively, and implement the [SHRINCS](https://github.com/BlockstreamResearch/shrincs-simplicity-verifier) verification logic.

## Usage

Unlike ECDSA and Schnorr signatures which are small (less than 520 bytes) and can be pushed to the stack as a single element, SHRINCS has to be split into parts.

### Signature structure

**Stateless signature stack layout:**

| Position | Element | Size | Description |
| :---: | :--- | :--- | :--- | 
| `[-11]` | `sf part` | 16 bytes |  |
| `[-10]` | `fors_R` | 32 bytes |  |
| `[-9..-5]` | `fors_part` (x5) | 368 bytes each |  |
| `[-4..-3]` | `xmss_layer` (x2) | 484 bytes each |  |
| `[-2]` | `sighash type` (optional) | 1 byte |  |
| `[-1]` | `q` | 0 byte | **Type Flag:** `MINIMALDATA` empty array indicating a Stateless signature (`q=0`) |

> [!IMPORTANT]
> **Block Signatures vs. SIGHASH Bytes**
> Standard UTXO transaction signatures append a 1-byte SIGHASH flag (e.g., `0x01` for `SIGHASH_ALL`) to the signature. However, **Block Signatures (Dynafed) DO NOT use a SIGHASH byte**.
> 

So, in a script, the required push order is as follows: `<sf> <R> <fp1> <fp2> <fp3> <fp4> <fp5> <xmssl1> <xmssl2> [<sighash_type>] <0>`

**Stateful signature stack layout:**

State (q) from 1 to 159 means leaf in a uxmss tree, so for q = 159 merkle path consists of 158 leaves, otherwise q represents the number of Merkle path leaves (mpl).

| Position | Element | Size |
| :---: | :--- | :--- |
| `[-(4 + mpl)]` | `sl part` | 16 bytes |
| `[-(3 + mpl)]` | `wots` | 292 bytes |
| `[-(2 + mpl)..-3]` | `merkle path` | 16 bytes each leaf |
| `[-2]` | `sighash type` | 1 byte |
| `[-1]` | `q` | 1 byte |

So, in a script, the required push order is as follows (example for `q = 3`): `<sl> <wots> <mp1> <mp2> <mp3> <sighash_type> <q>`

### Opcodes

Both opcodes consume the signature components and public key(s) from the stack, verify the signature, and push exactly one element (`True` or `False`) back to the stack.

**OP_SHRINCS (Single Signature)**
Behaves similarly to the legacy `OP_CHECKSIG`. The script structure is:
```text
<sig_components> <pubkey> OP_SHRINCS
```

**OP_MULTISHRINCS (Multisig)**
Designed for threshold signature schemes (e.g., 2-of-3), limited to a maximum of 20 public keys. The script structure is:
```text
<sig1_components> <sig2_components> OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_MULTISHRINCS
```

> **Note:** Unlike the legacy `OP_CHECKMULTISIG`, `OP_MULTISHRINCS` strictly adheres to `CLEANSTACK` rules and **does not** require a dummy `OP_0` element to be pushed before the signatures. The opcode dynamically parses the required number of signature components based on the `q` flag of each signature.