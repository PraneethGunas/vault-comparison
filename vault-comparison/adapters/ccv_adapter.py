"""CCV vault adapter.

Wraps pymatt's Vault/Unvaulting contracts and ContractManager to expose
the uniform VaultAdapter interface. Requires a Merkleize Bitcoin node
with CCV support on regtest.
"""

import os
import sys
from pathlib import Path
from typing import List, Optional

from adapters.base import VaultAdapter, VaultState, UnvaultState, TxRecord
from harness.rpc import RegTestRPC
from harness.metrics import TxMetrics

# Add pymatt to the Python path
PYMATT_REPO = Path(__file__).resolve().parents[2] / "pymatt"
PYMATT_VAULT = PYMATT_REPO / "examples" / "vault"


def _ensure_ccv_imports():
    """Lazy-load the CCV vault modules."""
    paths_to_add = [str(PYMATT_REPO / "src"), str(PYMATT_VAULT)]
    for p in paths_to_add:
        if p not in sys.path:
            sys.path.insert(0, p)

    from dotenv import load_dotenv
    load_dotenv(PYMATT_REPO / ".env")

    from matt.btctools import key
    from matt.btctools.auth_proxy import AuthServiceProxy
    from matt.manager import ContractManager, SchnorrSigner
    from matt.utils import make_ctv_template
    from vault_contracts import Vault, Unvaulting

    return {
        "key": key,
        "AuthServiceProxy": AuthServiceProxy,
        "ContractManager": ContractManager,
        "SchnorrSigner": SchnorrSigner,
        "make_ctv_template": make_ctv_template,
        "Vault": Vault,
        "Unvaulting": Unvaulting,
    }


def _hash_to_hex(h) -> str:
    """Convert a pymatt hash to hex string.

    COutPoint.hash is a uint256 (int), CTransaction.hash is already a hex str.
    """
    if isinstance(h, int):
        return h.to_bytes(32, "big").hex()
    if isinstance(h, str):
        return h
    if isinstance(h, bytes):
        return h.hex()
    return str(h)


class CCVAdapter(VaultAdapter):

    @property
    def name(self) -> str:
        return "ccv"

    @property
    def node_mode(self) -> str:
        return "ccv"

    @property
    def description(self) -> str:
        return "CCV+CTV vault (BIP 443 + BIP 119) via pymatt"

    def setup(self, rpc: RegTestRPC, locktime: int = 10, **kwargs) -> None:
        self.rpc = rpc
        self.locktime = locktime
        self._mods = _ensure_ccv_imports()

        # Key material (same as test_vault.py and attack common.py)
        self.unvault_priv_key = self._mods["key"].ExtendedKey.deserialize(
            "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMb"
            "JhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN"
        )
        self.recover_priv_key = self._mods["key"].ExtendedKey.deserialize(
            "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxS"
            "erNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ"
        )

        # Build the vault contract
        self.vault_contract = self._mods["Vault"](
            None,  # alternate_pk = None (NUMS key)
            self.locktime,
            self.recover_priv_key.pubkey[1:],
            self.unvault_priv_key.pubkey[1:],
        )

        # Connect the pymatt AuthServiceProxy (it uses its own RPC client)
        rpc_user = os.getenv("RPC_USER", "rpcuser")
        rpc_password = os.getenv("RPC_PASSWORD", "rpcpass")
        rpc_host = os.getenv("RPC_HOST", "localhost")
        rpc_port = os.getenv("RPC_PORT", "18443")
        wallet_name = os.getenv("WALLET_NAME", "testwallet")

        self._pymatt_rpc = self._mods["AuthServiceProxy"](
            f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}/wallet/{wallet_name}"
        )
        self._manager = self._mods["ContractManager"](
            self._pymatt_rpc, mine_automatically=True, poll_interval=0.01
        )
        self._signer = self._mods["SchnorrSigner"](self.unvault_priv_key)

        # Track CTV templates for withdrawal
        self._ctv_templates = {}

    def create_vault(self, amount_sats: int) -> VaultState:
        """Fund a new vault instance via ContractManager."""
        instance = self._manager.fund_instance(self.vault_contract, amount_sats)
        vault_txid = _hash_to_hex(instance.outpoint.hash)

        return VaultState(
            vault_txid=vault_txid,
            amount_sats=amount_sats,
            vault_address=self.vault_contract.get_address() if hasattr(self.vault_contract, "get_address") else "",
            extra={"instance": instance},
        )

    def trigger_unvault(self, vault: VaultState, dest_address: str = None) -> UnvaultState:
        """Trigger the vault into unvaulting state."""
        instance = vault.extra["instance"]

        # Generate a destination address if not provided
        if not dest_address:
            dest_address = self._pymatt_rpc.getnewaddress("withdraw-dest")

        # Build CTV template for the withdrawal
        withdraw_amount = vault.amount_sats - 2000  # small fee margin
        ctv_template = self._mods["make_ctv_template"](
            [(dest_address, withdraw_amount)],
            nSequence=self.locktime,
        )
        ctv_hash = ctv_template.get_standard_template_hash(0)

        # Trigger
        [unvault_instance] = instance("trigger", signer=self._signer)(
            out_i=0, ctv_hash=ctv_hash
        )

        # Store template for withdrawal
        self._ctv_templates[ctv_hash] = ctv_template

        unvault_txid = _hash_to_hex(unvault_instance.outpoint.hash)

        return UnvaultState(
            unvault_txid=unvault_txid,
            amount_sats=vault.amount_sats,
            blocks_remaining=self.locktime,
            extra={
                "instance": unvault_instance,
                "vault_instance": instance,
                "ctv_hash": ctv_hash,
                "ctv_template": ctv_template,
                "dest_address": dest_address,
            },
        )

    def complete_withdrawal(self, unvault: UnvaultState, path: str = "hot") -> TxRecord:
        """Complete the withdrawal after timelock expires.

        CCV only supports path="hot" (normal withdrawal after CSV).
        There is no CCV cold-sweep tx — use recover() for emergency escape.
        """
        if path != "hot":
            raise ValueError(
                f"CCV does not have a cold-sweep path. Use recover() instead. "
                f"Got path={path!r}"
            )
        instance = unvault.extra["instance"]
        ctv_hash = unvault.extra["ctv_hash"]
        ctv_template = unvault.extra["ctv_template"]

        # Build the withdrawal transaction
        spend_tx, _ = self._manager.get_spend_tx(
            (instance, "withdraw", {"ctv_hash": ctv_hash})
        )
        spend_tx.wit.vtxinwit = [
            self._manager.get_spend_wit(instance, "withdraw", {"ctv_hash": ctv_hash})
        ]
        # Fill in the CTV template fields
        spend_tx.nVersion = ctv_template.nVersion
        spend_tx.nLockTime = ctv_template.nLockTime
        spend_tx.vin[0].nSequence = ctv_template.vin[0].nSequence
        spend_tx.vout = ctv_template.vout

        # Mine enough blocks for CSV
        self._mine(self.locktime)

        # Broadcast and confirm
        self._manager.spend_and_wait(instance, spend_tx)

        txid = _hash_to_hex(instance.spending_tx.hash) if instance.spending_tx else ""

        return TxRecord(
            txid=txid,
            label="withdraw",
            raw_hex=spend_tx.serialize().hex() if hasattr(spend_tx, "serialize") else "",
            amount_sats=unvault.amount_sats - 2000,
        )

    def recover(self, state) -> TxRecord:
        """Execute emergency recovery (no key needed — just out_i)."""
        if isinstance(state, VaultState):
            instance = state.extra["instance"]
            amount = state.amount_sats
        elif isinstance(state, UnvaultState):
            instance = state.extra["instance"]
            amount = state.amount_sats
        else:
            raise ValueError(f"Cannot recover from {type(state)}")

        instance("recover")(out_i=0)

        txid = _hash_to_hex(instance.spending_tx.hash) if instance.spending_tx else ""

        return TxRecord(
            txid=txid,
            label="recover",
            amount_sats=amount,
        )

    # ── Internals & Capabilities ────────────────────────────────────

    def get_internals(self) -> dict:
        return {
            "pymatt_rpc": self._pymatt_rpc,
            "manager": self._manager,
            "vault_contract": self.vault_contract,
            "unvaulting_contract": self.unvaulting_contract,
            "unvault_priv_key": self.unvault_priv_key,
            "recover_priv_key": self.recover_priv_key,
            "mods": self._mods,
        }

    def supports_revault(self) -> bool:
        return True

    def supports_batched_trigger(self) -> bool:
        return True

    def supports_keyless_recovery(self) -> bool:
        return True  # recover clause requires no signature

    # ── Revault ──────────────────────────────────────────────────────

    def trigger_revault(self, vault: VaultState, withdraw_sats: int) -> tuple:
        """Trigger a partial withdrawal, revaulting the remainder."""
        instance = vault.extra["instance"]

        dest_address = self._pymatt_rpc.getnewaddress("partial-withdraw")
        ctv_template = self._mods["make_ctv_template"](
            [(dest_address, withdraw_sats)],
            nSequence=self.locktime,
        )
        ctv_hash = ctv_template.get_standard_template_hash(0)

        revault_amount = vault.amount_sats - withdraw_sats

        spends = [
            (instance, "trigger_and_revault", {
                "out_i": 0,
                "revault_out_i": 1,
                "ctv_hash": ctv_hash,
            }),
        ]
        spend_tx, sighashes = self._manager.get_spend_tx(
            spends, output_amounts={1: revault_amount}
        )

        from matt.btctools import key as keymod
        sigs = [keymod.sign_schnorr(self.unvault_priv_key.privkey, sh) for sh in sighashes]

        spend_tx.wit.vtxinwit = []
        for i, (inst, action, args) in enumerate(spends):
            spend_tx.wit.vtxinwit.append(
                self._manager.get_spend_wit(inst, action, {**args, "sig": sigs[i]})
            )

        result_instances = self._manager.spend_and_wait([instance], spend_tx)

        # result_instances should contain [Unvaulting, Vault]
        unvault_inst = None
        revault_inst = None
        for inst in result_instances:
            if isinstance(inst.contract, self._mods["Unvaulting"]):
                unvault_inst = inst
            elif isinstance(inst.contract, self._mods["Vault"]):
                revault_inst = inst

        self._ctv_templates[ctv_hash] = ctv_template

        unvault_state = UnvaultState(
            unvault_txid=_hash_to_hex(unvault_inst.outpoint.hash) if unvault_inst else "",
            amount_sats=withdraw_sats,
            blocks_remaining=self.locktime,
            extra={
                "instance": unvault_inst,
                "ctv_hash": ctv_hash,
                "ctv_template": ctv_template,
            },
        )
        revault_state = VaultState(
            vault_txid=_hash_to_hex(revault_inst.outpoint.hash) if revault_inst else "",
            amount_sats=revault_amount,
            extra={"instance": revault_inst},
        )
        return unvault_state, revault_state

    # ── Batched trigger ──────────────────────────────────────────────

    def trigger_batched(self, vaults: List[VaultState]) -> UnvaultState:
        """Trigger multiple vault UTXOs in a single transaction."""
        dest_address = self._pymatt_rpc.getnewaddress("batched-withdraw")
        total = sum(v.amount_sats for v in vaults)
        withdraw_amount = total - 2000

        ctv_template = self._mods["make_ctv_template"](
            [(dest_address, withdraw_amount)],
            nSequence=self.locktime,
        )
        ctv_hash = ctv_template.get_standard_template_hash(0)

        instances = [v.extra["instance"] for v in vaults]

        # First vault uses trigger_and_revault if there's remainder, else trigger
        spends = []
        for inst in instances:
            spends.append((inst, "trigger", {"out_i": 0, "ctv_hash": ctv_hash}))

        spend_tx, sighashes = self._manager.get_spend_tx(spends)

        from matt.btctools import key as keymod
        sigs = [keymod.sign_schnorr(self.unvault_priv_key.privkey, sh) for sh in sighashes]

        spend_tx.wit.vtxinwit = []
        for i, (inst, action, args) in enumerate(spends):
            spend_tx.wit.vtxinwit.append(
                self._manager.get_spend_wit(inst, action, {**args, "sig": sigs[i]})
            )

        result_instances = self._manager.spend_and_wait(instances, spend_tx)

        unvault_inst = result_instances[0] if result_instances else None
        self._ctv_templates[ctv_hash] = ctv_template

        return UnvaultState(
            unvault_txid=_hash_to_hex(unvault_inst.outpoint.hash) if unvault_inst else "",
            amount_sats=withdraw_amount,
            blocks_remaining=self.locktime,
            extra={
                "instance": unvault_inst,
                "ctv_hash": ctv_hash,
                "ctv_template": ctv_template,
            },
        )

    # ── Metrics enrichment ───────────────────────────────────────────

    def collect_tx_metrics(self, record: TxRecord, rpc: RegTestRPC) -> TxMetrics:
        metrics = super().collect_tx_metrics(record, rpc)
        metrics.script_type = "p2tr_ccv"
        metrics.csv_blocks = self.locktime if record.label == "withdraw" else 0
        return metrics

    # ── Internal ─────────────────────────────────────────────────────

    def _mine(self, n: int) -> None:
        addr = self._pymatt_rpc.getnewaddress()
        self._pymatt_rpc.generatetoaddress(n, addr)
