"""Abstract base adapter for covenant vault implementations.

Every vault adapter must implement this interface. Experiments are written
against this interface and run against any adapter.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from harness.rpc import RegTestRPC
from harness.metrics import TxMetrics


@dataclass
class TxRecord:
    """A broadcast transaction with its context."""
    txid: str
    label: str  # "tovault", "unvault", "withdraw", "recover", "tohot", "tocold"
    raw_hex: str = ""
    amount_sats: int = 0


@dataclass
class VaultState:
    """Opaque handle to a funded vault. Adapter-specific internals go in `extra`."""
    vault_txid: str
    amount_sats: int
    vault_address: str = ""
    extra: Any = None  # Adapter-specific (VaultPlan, ContractInstance, etc.)


@dataclass
class UnvaultState:
    """Handle to an unvaulting-in-progress."""
    unvault_txid: str
    amount_sats: int
    blocks_remaining: int = 0
    extra: Any = None


class VaultAdapter(ABC):
    """Interface that every covenant vault adapter must implement."""

    # ── Identity ─────────────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier: 'ctv', 'ccv', 'opvault', 'cat_csfs'."""
        ...

    @property
    @abstractmethod
    def node_mode(self) -> str:
        """Argument for switch-node.sh: 'inquisition', 'ccv'."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable one-liner."""
        ...

    # ── Setup / teardown ─────────────────────────────────────────────

    @abstractmethod
    def setup(self, rpc: RegTestRPC, **kwargs) -> None:
        """Initialize the adapter. Called once per experiment run.

        The adapter should create wallets, fund them, and prepare
        whatever internal state it needs. The regtest chain is assumed
        to be freshly reset.
        """
        ...

    def teardown(self) -> None:
        """Optional cleanup."""
        pass

    # ── Core vault lifecycle ─────────────────────────────────────────

    @abstractmethod
    def create_vault(self, amount_sats: int) -> VaultState:
        """Deposit funds into a new vault. Returns a handle to the vault."""
        ...

    @abstractmethod
    def trigger_unvault(self, vault: VaultState) -> UnvaultState:
        """Start the unvaulting process. Broadcasts the trigger/unvault tx."""
        ...

    @abstractmethod
    def complete_withdrawal(self, unvault: UnvaultState, path: str = "hot") -> TxRecord:
        """Complete the withdrawal after timelock expires.

        Args:
            unvault: Handle from trigger_unvault().
            path:    Withdrawal path.  The only universally supported value
                     is ``"hot"`` (wait for timelock, then broadcast the
                     final withdrawal tx).  ``"cold"`` is CTV-specific and
                     should NOT be used in cross-covenant experiments — call
                     ``recover()`` instead.

        Path semantics per covenant:

            CTV:      "hot" → tohot_tx (to hot wallet, after CSV).
                      "cold" → tocold_tx (immediate sweep to cold wallet).
                      recover() delegates to complete_withdrawal(path="cold").
                      These are two DISTINCT CTV-locked transactions baked
                      into the vault plan at creation time.

            CCV:      "hot" → withdraw via CTV template (after CSV).
                      "cold" has no meaning — CCV doesn't have a separate
                      cold-sweep transaction.  Emergency escape uses
                      recover() (keyless, any-time).

            OP_VAULT: "hot" → withdrawal_tx (CTV-locked, after spend_delay).
                      "cold" internally delegates to recover() (authorized
                      recovery).  There is no distinct cold-sweep tx —
                      OP_VAULT's recovery IS the cold path.

        For cross-covenant experiments: always use complete_withdrawal()
        for the normal happy-path withdrawal, and recover() for emergency
        recovery.  Never branch on path="cold" in comparative code.
        """
        ...

    @abstractmethod
    def recover(self, state) -> TxRecord:
        """Execute emergency recovery.

        ``state`` can be a VaultState or UnvaultState — recovery should work
        from either position in the lifecycle.

        Recovery semantics per covenant:

            CTV:      Broadcasts tocold_tx (the CTV-locked cold sweep).
                      Only works from UnvaultState (must trigger first).
                      Requires the CTV witness but no runtime key.

            CCV:      Keyless recovery — anyone can broadcast.  Works from
                      VaultState or UnvaultState.  No key material needed.

            OP_VAULT: Authorized recovery — requires recoveryauth key
                      signature.  Works from VaultState or UnvaultState.
                      This is OP_VAULT's anti-griefing design.
        """
        ...

    # ── Internals & Capabilities ────────────────────────────────────

    def get_internals(self) -> dict:
        """Expose adapter-specific internals for covenant-specific experiments.

        Returns a dict of internal objects (plans, executors, RPC clients,
        contract instances) that covenant-specific experiments need.

        Cross-adapter experiments MUST NOT call this method. Only experiments
        tagged with a specific covenant should use it.

        Convention: keys use the adapter's naming scheme, not a generic one.
        """
        return {}

    def capabilities(self) -> dict:
        """Programmatic capability discovery for experiments and agents."""
        return {
            "revault": self.supports_revault(),
            "batched_trigger": self.supports_batched_trigger(),
            "keyless_recovery": self.supports_keyless_recovery(),
            "max_batch_size": None,
            "recovery_requires_key": not self.supports_keyless_recovery(),
        }

    # ── Capabilities ─────────────────────────────────────────────────

    def supports_revault(self) -> bool:
        """Can this vault partially withdraw and revault the remainder?"""
        return False

    def supports_batched_trigger(self) -> bool:
        """Can multiple vault UTXOs be triggered in a single tx?"""
        return False

    def supports_keyless_recovery(self) -> bool:
        """Can recovery be triggered without any key material?"""
        return False

    # ── Optional operations ──────────────────────────────────────────

    def trigger_revault(self, vault: VaultState, withdraw_sats: int) -> tuple:
        """Trigger a partial withdrawal with revault.

        Returns (UnvaultState, VaultState) — the unvaulting portion and
        the revaulted remainder.
        """
        raise NotImplementedError(f"{self.name} does not support revaulting")

    def trigger_batched(self, vaults: List[VaultState]) -> UnvaultState:
        """Trigger multiple vaults in a single transaction."""
        raise NotImplementedError(f"{self.name} does not support batched triggers")

    # ── Metrics collection ───────────────────────────────────────────

    def collect_tx_metrics(self, record: TxRecord, rpc: RegTestRPC) -> TxMetrics:
        """Build a TxMetrics from a broadcast transaction.

        Default implementation uses RPC to look up vsize, weight, fee.
        Adapters can override to add script_type, witness details, etc.
        """
        info = rpc.get_tx_info(record.txid)
        fee = rpc.get_tx_fee_sats(record.txid)
        return TxMetrics(
            label=record.label,
            txid=record.txid,
            vsize=info["vsize"],
            weight=info["weight"],
            fee_sats=fee,
            num_inputs=len(info["vin"]),
            num_outputs=len(info["vout"]),
            amount_sats=record.amount_sats,
        )

    # ── Mining helper ────────────────────────────────────────────────

    def mine_blocks(self, n: int) -> None:
        """Mine n blocks on the regtest chain. Requires self.rpc to be set."""
        if hasattr(self, "rpc") and self.rpc:
            self.rpc.mine(n)
