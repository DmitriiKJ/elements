#!/usr/bin/env python3
"""DropKick sandbox: a local web page over a private elementsd regtest node.

    python3 dropkick_web/server.py [--port 8765] [--elementsd build/bin/elementsd]

Then open http://127.0.0.1:8765/.
"""

import argparse
import copy
import json
import os
import signal
import threading
import traceback
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import dklib
from dklib import (
    COMMITMENT_DEPTH,
    KEY_KINDS,
    OUT_KINDS,
    REVEAL_FEE,
    SCRIPT_KINDS,
    SF_SHAPE_UNBALANCED,
    DropKickClaim,
    DropKickPayload,
    DropKickWitness,
    ExtKey,
    build_agg_tree,
    build_anchor,
    build_plain_spend,
    build_reveal,
    commitment,
    decode_tx,
    input_spec,
    make_publication_script,
    new_eckey,
    new_unique_script,
    outpoint,
    payload_from_spk,
    required_fee,
    shrincs,
    verify_reveal,
)
from node import PERIOD, Node
from test_framework.authproxy import JSONRPCException
from test_framework.crypto.bip32 import HARDENED
from test_framework.dropkick import parse_publication_script

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
DEFAULT_FUND = 200000
KIND_LABELS = {"p2pkh": "P2PKH", "p2wpkh": "P2WPKH", "p2sh_p2wpkh": "P2SH-P2WPKH", "p2sh": "P2SH", "p2wsh": "P2WSH"}
WIT_NAMES = {1: "public key", 2: "extended private key", 3: "script"}


class ApiError(Exception):
    pass


def rpc_message(e):
    return e.error.get("message", str(e.error)) if isinstance(e, JSONRPCException) else str(e)


# --- persistent state --------------------------------------------------------

def empty_state():
    return {"qday_start": None, "xprv_seed": None, "next_id": 1,
            "utxos": [], "pqkeys": [], "batches": [], "reveals": []}


class Store:
    def __init__(self, path):
        self.path = path
        self.data = empty_state()
        if os.path.exists(path):
            with open(path) as f:
                self.data = json.load(f)

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=1)
        os.replace(tmp, self.path)

    def new_id(self, prefix):
        n = self.data["next_id"]
        self.data["next_id"] = n + 1
        return f"{prefix}{n}"

    def find(self, collection, item_id):
        for item in self.data[collection]:
            if item["id"] == item_id:
                return item
        raise ApiError(f"unknown id {item_id}")

    def entry(self, entry_id):
        for batch in self.data["batches"]:
            for e in batch["entries"]:
                if e["id"] == entry_id:
                    return batch, e
        raise ApiError(f"unknown commitment {entry_id}")


# --- the sandbox -------------------------------------------------------------

def parse_path(text):
    path = []
    for part in filter(None, text.strip().replace("'", "h").split("/")):
        if part == "m":
            continue
        hardened = part.endswith("h")
        index = int(part.rstrip("h"))
        if not 0 <= index < HARDENED:
            raise ApiError(f"path step out of range: {part}")
        path.append(index + HARDENED if hardened else index)
    return path


def format_path(path):
    return "m/" + "/".join(f"{p - HARDENED}h" if p >= HARDENED else str(p) for p in path) if path else "m"


class Sandbox:
    def __init__(self, node, store):
        self.node = node
        self.store = store
        self.lock = threading.Lock()

    @property
    def s(self):
        return self.store.data

    def start(self):
        self.node.start(self.s["qday_start"])

    # --- chain -------------------------------------------------------------

    def status(self):
        return {
            "height": self.node.height(),
            "dropkick": self.node.dropkick_status(),
            "enforced": self.node.dropkick_enforced(),
            "qday_start": self.s["qday_start"],
            "balance": self.node.balance(),
            "commitment_depth": COMMITMENT_DEPTH,
            "period": PERIOD,
        }

    def mine(self, body):
        n = int(body.get("n", 1))
        if not 1 <= n <= 5000:
            raise ApiError("mine between 1 and 5000 blocks at a time")
        self.node.mine(n)
        return self.status()

    def qday(self, body):
        if self.s["qday_start"] is not None:
            raise ApiError("Q-day has already happened on this chain; reset to start over")
        height = self.node.height()
        self.s["qday_start"] = (height // PERIOD + 1) * PERIOD
        self.store.save()
        self.node.restart(self.s["qday_start"])
        mined = self.node.mine_until_active()
        return dict(self.status(), mined=mined)

    def reset(self, body):
        self.node.wipe()
        self.store.data = empty_state()
        self.store.save()
        self.node.start(None)
        return self.status()

    # --- outputs -----------------------------------------------------------

    def xprv_seed(self):
        if self.s["xprv_seed"] is None:
            self.s["xprv_seed"] = os.urandom(32).hex()
        return self.s["xprv_seed"]

    def fund(self, body):
        kind = body.get("kind")
        if kind not in OUT_KINDS:
            raise ApiError(f"unknown output type {kind}")
        amount = int(body.get("amount") or DEFAULT_FUND)
        if amount < 10000:
            raise ApiError("fund at least 10000 sat, or the output cannot pay for its own rescue")
        source = body.get("key_source", "new")

        if kind in SCRIPT_KINDS:
            script_hex = (body.get("script_hex") or "").strip()
            script = bytes.fromhex(script_hex) if script_hex else bytes(new_unique_script())
            key = {"type": "script", "script": script.hex()}
        elif source == "new":
            key = {"type": "ec", "secret": new_eckey().get_bytes().hex(), "compressed": True}
        elif source == "new_uncompressed":
            if kind != "p2pkh":
                raise ApiError("uncompressed keys are only standard in P2PKH")
            key = {"type": "ec", "secret": new_eckey(False).get_bytes().hex(), "compressed": False}
        elif source == "reuse":
            other = self.store.find("utxos", body.get("reuse_utxo"))
            if other["key"]["type"] == "script":
                raise ApiError("that output is locked by a script, not a key")
            key = copy.deepcopy(other["key"])
            if key["type"] == "ec" and not key["compressed"] and kind != "p2pkh":
                raise ApiError("uncompressed keys are only standard in P2PKH")
        elif source == "xprv":
            key = {"type": "xprv", "path": parse_path(body.get("xprv_path") or "m/0")}
        else:
            raise ApiError(f"unknown key source {source}")

        utxo = {"id": self.store.new_id("u"), "kind": kind, "key": key, "amount": amount}
        spec = input_spec(utxo, self.xprv_seed() if key["type"] == "xprv" else None)
        txid, vout = self.node.send_to_spk(spec["spk"], amount)
        self.node.mine(1)
        utxo.update(txid=txid, vout=vout, spk=bytes(spec["spk"]).hex(),
                    witness=spec["witness"].hex(), wit_type=spec["wit_type"],
                    status="funded", height=self.node.height())
        self.s["utxos"].append(utxo)
        self.store.save()
        return utxo

    def spend(self, body):
        utxo = self.store.find("utxos", body.get("utxo"))
        spec = input_spec(utxo, self.s["xprv_seed"])
        dest = self.node.address_spk(self.node.new_address())
        tx = build_plain_spend(utxo, spec, dest)
        try:
            txid = self.node.rpc.sendrawtransaction(tx.serialize().hex())
        except JSONRPCException as e:
            return {"accepted": False, "reason": rpc_message(e)}
        self.node.mine(1)
        utxo.update(status="spent", spent_txid=txid)
        self.store.save()
        return {"accepted": True, "txid": txid}

    def refresh_utxos(self):
        for u in self.s["utxos"]:
            if u["status"] in ("funded", "committed"):
                if self.node.rpc.gettxout(u["txid"], u["vout"], True) is None:
                    u["status"] = "spent"
        self.store.save()

    # --- post-quantum keys ---------------------------------------------------

    def new_pqkey(self, body):
        seed_hex = (body.get("seed_hex") or "").strip()
        seed = bytes.fromhex(seed_hex) if seed_hex else os.urandom(48)
        if len(seed) != 48:
            raise ApiError("the SHRINCS seed is 48 bytes (96 hex characters)")
        depth = int(body.get("sf_depth") or 32)
        if not 1 <= depth <= 64:
            raise ApiError("stateful tree depth must be between 1 and 64")
        sk, pk = shrincs.shrincs_keygen(seed, bytes([SF_SHAPE_UNBALANCED, depth]))
        twin = next((k for k in self.s["pqkeys"] if k["pk"] == pk.hex()), None)
        if twin is not None:
            raise ApiError(f"this seed and depth give the same key as {twin['id']}; use {twin['id']} or another seed")
        key = {"id": self.store.new_id("k"), "label": body.get("label") or "",
               "seed": seed.hex(), "sf_depth": depth, "sk": sk.hex(), "pk": pk.hex(),
               "used_states": []}
        self.s["pqkeys"].append(key)
        self.store.save()
        return key

    def salvager(self, body):
        address = self.node.new_address()
        return {"address": address, "spk": self.node.address_spk(address).hex()}

    # --- commit --------------------------------------------------------------

    def commit(self, body):
        utxo_ids = body.get("utxos") or []
        if not utxo_ids:
            raise ApiError("select at least one output to commit")
        pq = self.store.find("pqkeys", body.get("pqkey"))
        sv_spk = bytes.fromhex((body.get("salvager_spk") or "").strip())
        sv_sat = int(body.get("sv_sat") or 0)
        if sv_sat and not sv_spk:
            raise ApiError("a salvage fee needs a salvager script pubkey")

        groups = {}
        for uid in utxo_ids:
            u = self.store.find("utxos", uid)
            if u["status"] != "funded":
                raise ApiError(f"{uid} is {u['status']}, only funded outputs can be committed")
            groups.setdefault(u["witness"], []).append(u)

        pk = bytes.fromhex(pq["pk"])
        attached = []
        witnesses, commits = [], []
        for w, members in groups.items():
            c = commitment(bytes.fromhex(w), pk, sv_spk, sv_sat)
            existing = self.open_entry(c.hex())
            if existing is not None:
                batch, e = existing
                e["utxos"] += [u["id"] for u in members]
                for u in members:
                    u.update(status="committed", batch=batch["id"])
                attached.append({"entry": e["id"], "batch": batch["id"], "utxos": [u["id"] for u in members]})
            else:
                witnesses.append(w)
                commits.append(c)
        if not commits:
            self.store.save()
            return {"batch": None, "attached": attached}
        root, paths = build_agg_tree(commits)

        txid, _ = self.node.send_to_spk(make_publication_script(root), 0)
        block_hash = self.node.mine(1)[0]
        batch = {"id": self.store.new_id("b"), "root": root.hex(), "pub_txid": txid,
                 "block_hash": block_hash, "height": self.node.height(),
                 "pqkey": pq["id"], "entries": []}
        for leaf_index, (w, c) in enumerate(zip(witnesses, commits)):
            members = groups[w]
            batch["entries"].append({
                "id": self.store.new_id("e"), "utxos": [u["id"] for u in members],
                "witness": w, "wit_type": members[0]["wit_type"],
                "salvager_spk": sv_spk.hex(), "sv_sat": sv_sat, "leaf_index": leaf_index,
                "agg_path": [h.hex() for h in paths[leaf_index]], "commitment": c.hex(),
                "revealed": False,
            })
            for u in members:
                u.update(status="committed", batch=batch["id"])
        self.s["batches"].append(batch)
        self.store.save()
        return {"batch": batch, "attached": attached}

    def open_entry(self, commitment_hex):
        """The deepest unrevealed record with this commitment, if any."""
        for batch in self.s["batches"]:
            for e in batch["entries"]:
                if e["commitment"] == commitment_hex and not e["revealed"]:
                    return batch, e
        return None

    # --- reveal --------------------------------------------------------------

    def reveal(self, body):
        entry_ids = body.get("entries") or []
        if not entry_ids:
            raise ApiError("select at least one commitment to open")
        picked = [self.store.entry(eid) for eid in entry_ids]
        pq_ids = {batch["pqkey"] for batch, _ in picked}
        if len(pq_ids) != 1:
            raise ApiError("one reveal carries one pk_pq: pick commitments made under the same key")
        pq = self.store.find("pqkeys", pq_ids.pop())

        mode = body.get("mode", "stateful")
        if mode == "stateful":
            used = pq["used_states"]
            ctr = body.get("state_ctr")
            ctr = (max(used) + 1 if used else 0) if ctr in (None, "") else int(ctr)
            if ctr in used and not body.get("allow_reuse"):
                raise ApiError(f"state {ctr} already signed once; reusing a one-time key is catastrophic")
        else:
            ctr = None

        anchors, anchor_of = [], {}
        salvagers, salvager_of = [], {}
        payload = DropKickPayload()
        payload.pk_pq = bytes.fromhex(pq["pk"])
        rescues, claims, value = [], [], 0
        height = self.node.height()
        depths = []
        wit_of = {}

        # Deepest batch first, so a commitment published twice opens against its oldest anchor.
        for batch, e in sorted(picked, key=lambda p: p[0]["height"]):
            if e["revealed"]:
                raise ApiError(f"{e['id']} has already been revealed")
            if e["commitment"] in wit_of:
                wit_idx = wit_of[e["commitment"]]
            else:
                if batch["id"] not in anchor_of:
                    anchor_of[batch["id"]] = len(anchors)
                    anchors.append(build_anchor(self.node.rpc, batch["pub_txid"]))
                    depths.append({"batch": batch["id"], "depth": height - batch["height"]})
                sv_idx = 0
                if e["salvager_spk"]:
                    if e["salvager_spk"] not in salvager_of:
                        salvager_of[e["salvager_spk"]] = len(salvagers)
                        salvagers.append(bytes.fromhex(e["salvager_spk"]))
                    sv_idx = salvager_of[e["salvager_spk"]] + 1
                wit_idx = wit_of[e["commitment"]] = len(payload.witnesses)
                payload.witnesses.append(DropKickWitness(
                    anchor_idx=anchor_of[batch["id"]], sv_idx=sv_idx, sv_sat=e["sv_sat"],
                    leaf_index=e["leaf_index"], agg_path=[bytes.fromhex(h) for h in e["agg_path"]],
                    wit_type=e["wit_type"], wit_data=bytes.fromhex(e["witness"])))
            for uid in e["utxos"]:
                u = self.store.find("utxos", uid)
                if u["status"] == "spent":
                    raise ApiError(f"{uid} is already spent")
                spec = input_spec(u, self.s["xprv_seed"])
                claims.append(DropKickClaim(input_idx=len(rescues), wit_idx=wit_idx,
                                            out_type=spec["out_type"], path=spec["path"]))
                rescues.append((outpoint(u), spec, u["amount"]))
                value += u["amount"]

        payload.anchors = anchors
        payload.salvagers = salvagers
        payload.claims = claims

        min_fee = required_fee(value)
        fee = body.get("fee")
        fee = max(REVEAL_FEE, min_fee) if fee in (None, "") else int(fee)
        dest_address = (body.get("dest_address") or "").strip() or self.node.new_address()
        dest = self.node.address_spk(dest_address)

        tx, sighash, payload_index = build_reveal(
            rescues, payload, bytes.fromhex(pq["sk"]), ctr, fee, dest)
        stateless = payload.sig[0] == shrincs.FXMSS_HEIGHT
        if ctr is not None and not stateless and ctr not in pq["used_states"]:
            pq["used_states"].append(ctr)
            self.store.save()

        raw = tx.serialize().hex()
        decoded = self.node.rpc.decoderawtransaction(raw)
        info = {
            "txid": decoded["txid"],
            "size": decoded["size"],
            "vsize": decoded["vsize"],
            "payload_bytes": len(payload.serialize()),
            "payload_index": payload_index,
            "sig_bytes": len(payload.sig),
            "sig_mode": "stateless" if stateless else "stateful",
            "state_ctr": None if stateless else ctr,
            "sighash": sighash.hex(),
            "value": value,
            "fee": fee,
            "required_fee": min_fee,
            "depths": depths,
            "enforced": self.node.dropkick_enforced(),
            "payload": describe_payload(payload),
            "outputs": [{"n": o["n"], "value": o.get("value"),
                         "type": o["scriptPubKey"].get("type"),
                         "hex": o["scriptPubKey"]["hex"][:80]} for o in decoded["vout"]],
            "hex": raw,
        }

        info["broadcast"] = body.get("action") != "check"
        if not info["broadcast"]:
            res = self.node.rpc.testmempoolaccept([raw], 0)[0]
            info.update(accepted=res["allowed"],
                        reason=res.get("reject-details") or res.get("reject-reason", ""))
            return info

        try:
            self.node.rpc.sendrawtransaction(raw, 0)
        except JSONRPCException as e:
            info.update(accepted=False, reason=rpc_message(e))
            return info

        if body.get("mine", True):
            self.node.mine(1)
        for _, e in picked:
            e["revealed"] = True
            for uid in e["utxos"]:
                self.store.find("utxos", uid).update(status="spent", spent_txid=info["txid"])
        self.s["reveals"].append({"id": self.store.new_id("r"), "txid": info["txid"],
                                  "entries": entry_ids, "pqkey": pq["id"],
                                  "sig_mode": info["sig_mode"], "state_ctr": info["state_ctr"],
                                  "value": value, "fee": fee, "vsize": info["vsize"]})
        self.store.save()
        info["accepted"] = True
        return info

    # --- transaction viewer ----------------------------------------------------

    def describe_utxo(self, u):
        key = u["key"]
        if key["type"] == "script":
            lock = "script"
        elif key["type"] == "xprv":
            lock = "xprv " + format_path(key["path"])
        else:
            lock = "key" if key["compressed"] else "uncompressed key"
        return f"{u['id']} · {KIND_LABELS[u['kind']]} · {lock} · {u['amount']:,} sat"

    def sandbox_notes(self, txid):
        """What a transaction means in the sandbox, as {title, detail, items} blocks."""
        notes = []
        reveal = next((r for r in self.s["reveals"] if r["txid"] == txid), None)
        spent = [u for u in self.s["utxos"] if u.get("spent_txid") == txid]
        funded = [u for u in self.s["utxos"] if u["txid"] == txid]

        if reveal is not None:
            batches = sorted({self.store.entry(e)[0]["id"] for e in reveal["entries"]})
            sig = reveal["sig_mode"] + (f" signature, state {reveal['state_ctr']}" if reveal["state_ctr"] is not None
                                        else " signature")
            notes.append({
                "title": f"DropKick reveal {reveal['id']}",
                "detail": f"Opens {len(reveal['entries'])} commitment(s) {', '.join(reveal['entries'])} "
                          f"from batch {', '.join(batches)} under PQ key {reveal['pqkey']}, {sig}. "
                          f"Rescues these outputs:",
                "items": [self.describe_utxo(u) for u in spent],
            })
        elif spent:
            notes.append({
                "title": "Ordinary spend",
                "detail": "Spends sandbox outputs with their legacy script only, without a DropKick payload:",
                "items": [self.describe_utxo(u) for u in spent],
            })

        for b in self.s["batches"]:
            if b["pub_txid"] == txid:
                notes.append({
                    "title": f"Commitment batch {b['id']}",
                    "detail": f"Publishes one aggregation root for {len(b['entries'])} witness record(s) "
                              f"under PQ key {b['pqkey']} in an OP_RETURN output; the node wallet pays for it, "
                              f"so the other outputs are its change and the fee. "
                              f"Each record covers the outputs sharing its witness:",
                    "items": [f"{e['id']} → {', '.join(e['utxos'])} ({WIT_NAMES[e['wit_type']]})"
                              for e in b["entries"]],
                })

        if funded:
            notes.append({
                "title": "Funding",
                "detail": "Creates sandbox outputs locked to a hash-protected script:",
                "items": [f"output #{u['vout']}: {self.describe_utxo(u)}" for u in funded],
            })
        return notes

    def utxo_at(self, txid, vout):
        for u in self.s["utxos"]:
            if u["txid"] == txid and u["vout"] == vout:
                return u["id"]
        return None

    def tx(self, body):
        txid = (body.get("txid") or "").strip().lower()
        if len(txid) != 64:
            raise ApiError("a txid is 64 hex characters")
        try:
            info = self.node.rpc.getrawtransaction(txid, True)
        except JSONRPCException:
            raise ApiError(f"transaction {txid} is not in the mempool or the chain")

        height = self.node.height()
        block_height = None
        if info.get("blockhash"):
            block_height = self.node.rpc.getblockheader(info["blockhash"])["height"]

        inputs = []
        for n, vin in enumerate(info["vin"]):
            if "coinbase" in vin:
                inputs.append({"n": n, "coinbase": True})
                continue
            item = {"n": n, "txid": vin["txid"], "vout": vin["vout"],
                    "sandbox": self.utxo_at(vin["txid"], vin["vout"])}
            if vin.get("is_pegin"):
                item["type"] = "pegin"
            else:
                prev = self.node.rpc.getrawtransaction(vin["txid"], True)["vout"][vin["vout"]]
                item.update(type=prev["scriptPubKey"].get("type"), value=prev.get("value"),
                            spk=prev["scriptPubKey"]["hex"])
            inputs.append(item)

        tx = decode_tx(info["hex"])
        outputs, payload, roots = [], None, []
        for o in info["vout"]:
            spk = bytes.fromhex(o["scriptPubKey"]["hex"])
            role = None
            root = parse_publication_script(spk)
            if root is not None:
                role = "commitment root"
                roots.append(root.hex())
            elif not spk and o["scriptPubKey"].get("type") == "fee":
                role = "fee"
            elif payload is None and (p := payload_from_spk(spk)) is not None:
                role = "DropKick payload"
                payload = (o["n"], p)
            outputs.append({"n": o["n"], "value": o.get("value"), "type": o["scriptPubKey"].get("type"),
                            "spk": o["scriptPubKey"]["hex"], "role": role,
                            "address": o["scriptPubKey"].get("address"),
                            "sandbox": self.utxo_at(txid, o["n"])})

        for o in outputs:
            if o["role"] is not None:
                continue
            if o["sandbox"]:
                o["role"] = "sandbox output"
            elif payload is not None and o["n"] < payload[0]:
                o["role"] = "salvage payout"
            elif o["address"] and self.node.rpc.getaddressinfo(o["address"]).get("ismine"):
                o["role"] = "rescued funds" if payload is not None else "wallet change"

        result = {
            "txid": txid,
            "status": "confirmed" if block_height is not None else "mempool",
            "blockhash": info.get("blockhash"),
            "block_height": block_height,
            "confirmations": 0 if block_height is None else height - block_height + 1,
            "size": info["size"], "vsize": info["vsize"],
            "version": info["version"], "locktime": info["locktime"],
            "inputs": inputs, "outputs": outputs,
            "roots": roots,
            "notes": self.sandbox_notes(txid),
            "hex": info["hex"],
        }
        if payload is not None:
            index, p = payload
            sighash, valid = verify_reveal(tx, index, p)
            result["reveal"] = {
                "payload_index": index,
                "payload_bytes": len(p.serialize()),
                "sig_bytes": len(p.sig),
                "sig_mode": "stateless" if p.sig[:1] == bytes([shrincs.FXMSS_HEIGHT]) else "stateful",
                "sighash": sighash.hex(),
                "sig_valid": valid,
                "payload": describe_payload(p),
            }
        return result

    # --- snapshot for the pages ------------------------------------------------

    def state(self):
        self.refresh_utxos()
        seed = self.s["xprv_seed"]
        return {
            "status": self.status(),
            "utxos": self.s["utxos"],
            "pqkeys": [{k: v for k, v in key.items() if k != "sk"} for key in self.s["pqkeys"]],
            "batches": self.s["batches"],
            "reveals": self.s["reveals"],
            "xprv": None if seed is None else {
                "seed": seed, "xprv": ExtKey.from_seed(bytes.fromhex(seed)).serialize().hex()},
            "paths": {u["id"]: format_path(u["key"]["path"])
                      for u in self.s["utxos"] if u["key"]["type"] == "xprv"},
        }


def describe_payload(p):
    return {
        "version": p.version,
        "pk_pq": p.pk_pq.hex(),
        "anchors": [{"block_hash": a.block_hash[::-1].hex(), "tx_index": a.tx_index,
                     "tx_depth": len(a.tx_path), "tx_len": len(a.tx_data)} for a in p.anchors],
        "salvagers": [s.hex() for s in p.salvagers],
        "witnesses": [{"anchor_idx": w.anchor_idx, "sv_idx": w.sv_idx, "sv_sat": w.sv_sat,
                       "leaf_index": w.leaf_index, "wit_type": w.wit_type,
                       "wit_data": w.wit_data.hex()} for w in p.witnesses],
        "claims": [{"input_idx": c.input_idx, "wit_idx": c.wit_idx, "out_type": c.out_type,
                    "path": format_path(c.path)} for c in p.claims],
    }


# --- HTTP ----------------------------------------------------------------------

ROUTES = {
    ("GET", "/api/state"): lambda sb, body: sb.state(),
    ("GET", "/api/tx"): Sandbox.tx,
    ("POST", "/api/mine"): Sandbox.mine,
    ("POST", "/api/qday"): Sandbox.qday,
    ("POST", "/api/reset"): Sandbox.reset,
    ("POST", "/api/fund"): Sandbox.fund,
    ("POST", "/api/spend"): Sandbox.spend,
    ("POST", "/api/pqkey"): Sandbox.new_pqkey,
    ("POST", "/api/salvager"): Sandbox.salvager,
    ("POST", "/api/commit"): Sandbox.commit,
    ("POST", "/api/reveal"): Sandbox.reveal,
}

MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}


def json_default(o):
    if isinstance(o, Decimal):
        return float(o)
    if isinstance(o, bytes):
        return o.hex()
    raise TypeError(type(o).__name__)


def make_handler(sandbox):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body, default=json_default).encode()
            try:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the page was closed or reloaded before the answer was ready

        def _api(self, method):
            url = urlparse(self.path)
            route = ROUTES.get((method, url.path))
            if route is None:
                return self._send(404, {"error": "no such endpoint"})
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                body.update({k: v[0] for k, v in parse_qs(url.query).items()})
                with sandbox.lock:
                    result = route(sandbox, body)
            except (ApiError, ValueError) as e:
                return self._send(400, {"error": str(e)})
            except JSONRPCException as e:
                return self._send(400, {"error": "node: " + rpc_message(e)})
            except Exception as e:
                traceback.print_exc()
                return self._send(500, {"error": f"{type(e).__name__}: {e}"})
            self._send(200, result)

        def do_POST(self):
            self._api("POST")

        def do_GET(self):
            path = urlparse(self.path).path
            if path.startswith("/api/"):
                return self._api("GET")
            name = "index.html" if path in ("", "/") else path.lstrip("/")
            full = os.path.normpath(os.path.join(STATIC, name))
            if not full.startswith(STATIC) or not os.path.isfile(full):
                return self._send(404, b"not found", "text/plain")
            with open(full, "rb") as f:
                self._send(200, f.read(), MIME.get(os.path.splitext(full)[1], "application/octet-stream"))

    return Handler


def main():
    repo = dklib.REPO
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--elementsd", default=os.environ.get("ELEMENTSD", os.path.join(repo, "build", "bin", "elementsd")))
    parser.add_argument("--datadir", default=os.path.join(HERE, ".data"))
    args = parser.parse_args()

    store = Store(os.path.join(args.datadir, "state.json"))
    sandbox = Sandbox(Node(args.elementsd, os.path.join(args.datadir, "node")), store)
    print("starting elementsd ...", flush=True)
    sandbox.start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(sandbox))
    print(f"DropKick sandbox on http://127.0.0.1:{args.port}/", flush=True)
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print("stopping elementsd ...", flush=True)
        sandbox.node.stop()


if __name__ == "__main__":
    main()
