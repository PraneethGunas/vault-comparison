"""CTV vault adapter.

Wraps simple-ctv-vault's VaultScenario / VaultPlan to expose the
uniform VaultAdapter interface. Requires a CTV-enabled regtest node
(Bitcoin Inquisition or Jeremy Rubin's fork).
"""

from adapters.base import VaultAdapter, VaultState, UnvaultState, TxRecord
from harness.rpc import RegTestRPC
from harness.metrics import TxMetrics
from harness.module_loader import UpstreamModuleLoader
from config import CFG


class CTVAdapter(VaultAdapter):

    @property
    def name(self) -> str:
        return "ctv"

    @property
    def node_mode(self) -> str:
        return "inquisition"

    @property
    def description(self) -> str:
        return "CTV-only vault (BIP 119) via simple-ctv-vault"

    def setup(self, rpc: RegTestRPC, block_delay: int = 10, seed: bytes = b"compare", **kwargs) -> None:
        self.rpc = rpc
        self.block_delay = block_delay
        self.seed = seed
        self._vault_counter = 0

        # Load upstream modules via module_loader
        loader = UpstreamModuleLoader(
            repo_path=CFG.ctv_repo,
            evict_modules=["main", "rpc"],
        )
        mods = loader.load(["main", "rpc"])
        self.ctv_main = mods["main"]
        self.ctv_rpc = mods["rpc"]

        from bitcoin import SelectParams
        SelectParams("regtest")

        self.fee_wallet = self.ctv_main.Wallet.generate(b"fee-" + seed)
        self.cold_wallet = self.ctv_main.Wallet.generate(b"cold-" + seed)
        self.hot_wallet = self.ctv_main.Wallet.generate(b"hot-" + seed)

        # We'll use ctv_rpc's BitcoinRPC for CTV-specific operations
        self._ctv_rpc = self.ctv_rpc.BitcoinRPC(net_name="regtest")

        # Coin pool: mine once, split many times
        from harness.coin_pool import CoinPool
        from main import scan_utxos

        self._bank_wallet = self.ctv_main.Wallet.generate(b"bank-" + seed)
        self._pool = CoinPool(
            rpc=self._ctv_rpc,
            bank_wallet=self._bank_wallet,
            vault_module=self.ctv_main,
            scan_fn=scan_utxos,
            generate_wallet=self.ctv_main.Wallet.generate,
            get_address=lambda w: w.privkey.point.p2wpkh_address(network="regtest"),
            get_privkey=lambda w: w.privkey,
            mine_fn=lambda rpc, n, addr: rpc.generatetoaddress(n, addr),
            fee_address=self.fee_wallet.privkey.point.p2wpkh_address(network="regtest"),
        )

    def _unique_seed(self) -> bytes:
        """Generate a unique seed for each vault to avoid tx collisions."""
        self._vault_counter += 1
        return self.seed + b"-vault-" + str(self._vault_counter).encode()

    def create_vault(self, amount_sats: int) -> VaultState:
        """Fund a wallet, then create a vault of the specified amount."""
        coin, from_wallet = self._pool.fund(amount_sats, seed=self._unique_seed())

        plan = self.ctv_main.VaultPlan(
            self.hot_wallet.privkey.point,
            self.cold_wallet.privkey.point,
            self.fee_wallet.privkey.point,
            coin,
            block_delay=self.block_delay,
        )
        executor = self.ctv_main.VaultExecutor(plan, self._ctv_rpc, coin)

        # Broadcast the tovault transaction
        tovault_tx = plan.sign_tovault_tx(from_wallet.privkey)
        tovault_hex = tovault_tx.serialize().hex()
        txid = self._ctv_rpc.sendrawtransaction(tovault_hex)

        # Mine it to confirm
        self.ctv_main.generateblocks(self._ctv_rpc, 1)

        return VaultState(
            vault_txid=txid,
            amount_sats=plan.amount_at_step(1),
            extra={
                "plan": plan,
                "executor": executor,
                "coin": coin,
                "from_wallet": from_wallet,
            },
        )

    def trigger_unvault(self, vault: VaultState) -> UnvaultState:
        """Broadcast the unvault transaction (CTV-only, no signature needed)."""
        plan = vault.extra["plan"]
        executor = vault.extra["executor"]

        unvault_txid = executor.start_unvault()
        self.ctv_main.generateblocks(self._ctv_rpc, 1)

        return UnvaultState(
            unvault_txid=unvault_txid,
            amount_sats=plan.amount_at_step(2),
            blocks_remaining=self.block_delay,
            extra=vault.extra,
        )

    def complete_withdrawal(self, unvault: UnvaultState, path: str = "hot") -> TxRecord:
        """Complete withdrawal via hot or cold path.

        CTV is the only covenant with two distinct pre-committed withdrawal
        transactions:

            path="hot":  tohot_tx — sends to hot wallet after CSV timelock.
            path="cold": tocold_tx — immediate sweep to cold wallet (no delay).

        Both are CTV-locked at vault creation time.  recover() delegates to
        path="cold".
        """
        plan = unvault.extra["plan"]
        executor = unvault.extra["executor"]

        if path == "hot":
            # Mine enough blocks for CSV to pass
            self.ctv_main.generateblocks(self._ctv_rpc, self.block_delay)
            tx = executor.get_tohot_tx(self.hot_wallet.privkey)
            label = "tohot"
        else:
            tx = executor.get_tocold_tx()
            label = "tocold"

        tx_hex = tx.serialize().hex()
        txid = self._ctv_rpc.sendrawtransaction(tx_hex)
        self.ctv_main.generateblocks(self._ctv_rpc, 1)

        return TxRecord(
            txid=txid,
            label=label,
            raw_hex=tx_hex,
            amount_sats=plan.amount_at_step(3),
        )

    def recover(self, state) -> TxRecord:
        """CTV vaults use the cold sweep as the recovery mechanism.

        There is no separate 'recover' in CTV — the tocold path IS the
        emergency escape. This only works from the unvault state.
        """
        if isinstance(state, UnvaultState):
            return self.complete_withdrawal(state, path="cold")
        raise ValueError("CTV recovery only available from unvault state (cold sweep)")

    # ── Internals & Capabilities ────────────────────────────────────

    def get_internals(self) -> dict:
        return {
            "ctv_rpc": self._ctv_rpc,
            "ctv_main": self.ctv_main,
            "plan_class": self.ctv_main.VaultPlan,
            "executor_class": self.ctv_main.VaultExecutor,
            "fee_wallet": self.fee_wallet,
            "cold_wallet": self.cold_wallet,
            "hot_wallet": self.hot_wallet,
            "pool": self._pool,
        }

    def supports_revault(self) -> bool:
        return False

    def supports_batched_trigger(self) -> bool:
        return False

    def supports_keyless_recovery(self) -> bool:
        return False

    # ── Metrics enrichment ───────────────────────────────────────────

    def collect_tx_metrics(self, record: TxRecord, rpc: RegTestRPC) -> TxMetrics:
        metrics = super().collect_tx_metrics(record, rpc)

        if record.label == "tovault":
            metrics.script_type = "bare_ctv"
        elif record.label in ("tohot", "tocold"):
            metrics.script_type = "p2wsh_ctv"
            metrics.csv_blocks = self.block_delay if record.label == "tohot" else 0
        elif record.label == "unvault":
            metrics.script_type = "bare_ctv"

        return metrics
