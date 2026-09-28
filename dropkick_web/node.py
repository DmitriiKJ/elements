"""Lifecycle of the sandbox's own elementsd regtest node."""

import os
import shutil
import subprocess
import time

import dklib  # noqa: F401  (puts test/functional on sys.path)
from test_framework.authproxy import AuthServiceProxy, JSONRPCException
from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript
from test_framework.util import BITCOIN_ASSET

RPC_PORT = 18884
P2P_PORT = 18885
RPC_USER = "dropkick"
RPC_PASSWORD = "dropkick"
WALLET = "dropkick"

# The deployment uses short periods so that Q-day takes a few dozen blocks.
PERIOD = 16
NEVER = 2 ** 31
MATURE_HEIGHT = 110


class Node:
    def __init__(self, elementsd, datadir):
        self.elementsd = elementsd
        self.datadir = datadir
        self.proc = None
        self.rpc = None

    def _args(self, qday_start):
        start = NEVER if qday_start is None else qday_start
        return [
            self.elementsd,
            f"-datadir={self.datadir}",
            "-chain=elementsregtest",
            "-server=1",
            f"-rpcuser={RPC_USER}",
            f"-rpcpassword={RPC_PASSWORD}",
            f"-rpcport={RPC_PORT}",
            "-rpcservertimeout=99000",
            f"-port={P2P_PORT}",
            "-listen=0",
            "-connect=0",
            "-discover=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-listenonion=0",
            "-natpmp=0",
            "-printtoconsole=0",
            "-fallbackfee=0.0002",
            "-minrelaytxfee=0.00001",
            "-validatepegin=0",
            f"-con_parent_pegged_asset={BITCOIN_ASSET}",
            "-con_blocksubsidy=5000000000",
            "-con_connect_genesis_outputs=0",
            "-anyonecanspendaremine=0",
            "-walletrbf=0",
            "-con_bip34height=1",
            "-con_bip65height=1",
            "-con_bip66height=1",
            "-blindedaddresses=0",
            "-addresstype=bech32m",
            "-changetype=bech32m",
            "-txindex=1",
            "-datacarriersize=100000",
            f"-evbparams=dynafed:{NEVER}:::",
            f"-evbparams=dropkick:{start}::{PERIOD}:{PERIOD}",
        ]

    def _proxy(self):
        url = f"http://{RPC_USER}:{RPC_PASSWORD}@127.0.0.1:{RPC_PORT}"
        return AuthServiceProxy(url, timeout=900)

    def _stop_stray(self):
        """Stop a node left running by an earlier server on the same port."""
        try:
            self._proxy().stop()
        except Exception:
            return
        time.sleep(3)

    def start(self, qday_start):
        os.makedirs(self.datadir, exist_ok=True)
        self._stop_stray()
        log = open(os.path.join(self.datadir, "elementsd.stderr"), "w")
        self.proc = subprocess.Popen(self._args(qday_start), stdout=subprocess.DEVNULL, stderr=log)

        deadline = time.time() + 90
        while True:
            if self.proc.poll() is not None:
                with open(os.path.join(self.datadir, "elementsd.stderr")) as f:
                    raise RuntimeError("elementsd exited during startup: " + f.read()[-2000:])
            try:
                self.rpc = self._proxy()
                self.rpc.getblockcount()
                break
            except (JSONRPCException, OSError, ConnectionError):
                if time.time() > deadline:
                    raise RuntimeError("elementsd did not answer RPC in time")
                time.sleep(0.5)

        self._open_wallet()
        height = self.rpc.getblockcount()
        if height < MATURE_HEIGHT:
            self.mine(MATURE_HEIGHT - height)

    def _open_wallet(self):
        if WALLET in self.rpc.listwallets():
            return
        try:
            self.rpc.loadwallet(WALLET)
        except JSONRPCException:
            self.rpc.createwallet(WALLET)

    def stop(self):
        if self.proc is not None:
            try:
                self._proxy().stop()
            except Exception:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        self.rpc = None

    def restart(self, qday_start):
        self.stop()
        self.start(qday_start)

    def wipe(self):
        self.stop()
        shutil.rmtree(self.datadir, ignore_errors=True)

    # --- chain -------------------------------------------------------------

    def new_address(self):
        return self.rpc.getnewaddress("", "bech32m")

    def address_spk(self, address):
        return bytes.fromhex(self.rpc.getaddressinfo(address)["scriptPubKey"])

    def mine(self, n):
        return self.rpc.generatetoaddress(n, self.new_address())

    def height(self):
        return self.rpc.getblockcount()

    def dropkick_status(self):
        info = self.rpc.getdeploymentinfo()["deployments"]["dropkick"]
        if "bip9" in info:
            return info["bip9"]["status"]
        return "active" if info.get("active") else "defined"

    def dropkick_enforced(self):
        """Whether the mempool and the next block apply the DropKick rules."""
        return bool(self.rpc.getdeploymentinfo()["deployments"]["dropkick"].get("active"))

    def mine_until_active(self, max_blocks=20 * PERIOD):
        mined = 0
        while self.dropkick_status() != "active":
            if mined >= max_blocks:
                raise RuntimeError("deployment did not activate; status " + self.dropkick_status())
            self.mine(PERIOD)
            mined += PERIOD
        return mined

    # --- wallet ------------------------------------------------------------

    def send_to_spk(self, spk, amount):
        """Pay `amount` sat to a raw script pubkey from the node wallet; return (txid, vout)."""
        tx = CTransaction()
        tx.vout.append(CTxOut(amount, CScript(spk)))
        funded = self.rpc.fundrawtransaction(tx.serialize().hex())
        # signrawtransactionwithwallet makes invalid Schnorr signatures for the
        # wallet's P2TR coins here; the PSBT path signs them correctly.
        processed = self.rpc.walletprocesspsbt(self.rpc.converttopsbt(funded["hex"]))
        signed = self.rpc.finalizepsbt(processed["psbt"])
        if not signed["complete"]:
            raise RuntimeError("wallet could not sign the funding transaction")
        txid = self.rpc.sendrawtransaction(signed["hex"])
        decoded = self.rpc.decoderawtransaction(signed["hex"])
        vout = next(o["n"] for o in decoded["vout"] if o["scriptPubKey"]["hex"] == bytes(spk).hex())
        return txid, vout

    def balance(self):
        bal = self.rpc.getbalance()
        return float(bal.get("bitcoin", 0)) if isinstance(bal, dict) else float(bal)
