"""CAT+CSFS vault adapter.

Wraps simple-cat-csfs-vault's VaultPlan / VaultExecutor to expose the
uniform VaultAdapter interface. Requires an OP_CAT + OP_CSFS enabled
regtest node (Bitcoin Inquisition >= v28.0).

Uses the same Bitcoin Inquisition node as CTV — no additional node
build required.
"""

from adapters.base import VaultAdapter, VaultState, UnvaultState, TxRecord
from harness.rpc import RegTestRPC
from harness.metrics import TxMetrics
from harness.module_loader import UpstreamModuleLoader
from config import CFG


class CATCSFSAdapter(VaultAdapter):

    @property
    def name(self) -> str:
        return "cat_csfs"

    @property
    def node_mode(self) -> str:
        return "inquisition"

    @property
    def description(self) -> str:
        return "CAT+CSFS vault (BIP 347 + BIP 348) via simple-cat-csfs-vault"

    def setup(self, rpc: RegTestRPC, block_delay: int = 10, seed: bytes = b"compare", **kwargs) -> None:
        self.rpc = rpc
        self.block_delay = block_delay
        self.seed = seed
        self._vault_counter = 0

        # Load upstream modules via module_loader
        loader = UpstreamModuleLoader(
            repo_path=CFG.cat_csfs_repo,
            evict_modules=["main", "rpc", "vault", "taproot"],
        )
        mods = loader.load(["vault", "rpc", "taproot"])
        self.cat_vault = mods["vault"]
        self.cat_rpc = mods["rpc"]
        self.cat_taproot = mods["taproot"]

        from bitcoin import SelectParams
        SelectParams("regtest")

        self.fee_wallet = self.cat_vault.Wallet.generate(b"fee-" + seed)
        self.cold_wallet = self.cat_vault.Wallet.generate(b"cold-" + seed)
        self.hot_wallet = self.cat_vault.Wallet.generate(b"hot-" + seed)
        self.dest_wallet = self.cat_vault.Wallet.generate(b"dest-" + seed)

        # Use cat_rpc's BitcoinRPC for CAT+CSFS-specific operations
        self._cat_rpc = self.cat_rpc.BitcoinRPC(net_name="regtest")

        # Coin pool: mine once, split many times (shared with CTV)
        from harness.coin_pool import CoinPool
        from main import scan_utxos

        self._bank_wallet = self.cat_vault.Wallet.generate(b"bank-" + seed)
        self._pool = CoinPool(
            rpc=self._cat_rpc,
            bank_wallet=self._bank_wallet,
            vault_module=self.cat_vault,
            scan_fn=scan_utxos,
            generate_wallet=self.cat_vault.Wallet.generate,
            get_address=lambda w: w.p2wpkh_address,
            get_privkey=lambda w: w.privkey,
            mine_fn=lambda rpc, n, addr: rpc.generatetoaddress(n, addr),
            fee_address=self.fee_wallet.p2wpkh_address,
        )

    def _unique_seed(self) -> bytes:
        """Generate a unique seed for each vault to avoid tx collisions."""
        self._vault_counter += 1
        return self.seed + b"-vault-" + str(self._vault_counter).encode()

    def create_vault(self, amount_sats: int) -> VaultState:
        """Fund a wallet, then create a vault of the specified amount."""
        coin, from_wallet = self._pool.fund(amount_sats, seed=self._unique_seed())

        plan = self.cat_vault.VaultPlan(
            hot_wallet=self.hot_wallet,
            cold_wallet=self.cold_wallet,
            dest_wallet=self.dest_wallet,
            fee_wallet=self.fee_wallet,
            coin_in=coin,
            block_delay=self.block_delay,
        )
        executor = self.cat_vault.VaultExecutor(plan, self._cat_rpc)

        # Sign and broadcast tovault transaction
        tovault_tx = plan.sign_tovault(from_wallet.privkey)
        tovault_hex = tovault_tx.serialize().hex()
        txid = self._cat_rpc.sendrawtransaction(tovault_hex)

        # Mine to confirm
        self._cat_rpc.generatetoaddress(1, self.fee_wallet.p2wpkh_address)

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
        """Broadcast the trigger transaction (hot key + CSFS introspection)."""
        plan = vault.extra["plan"]
        executor = vault.extra["executor"]

        unvault_txid = executor.trigger_unvault()
        self._cat_rpc.generatetoaddress(1, self.fee_wallet.p2wpkh_address)

        return UnvaultState(
            unvault_txid=unvault_txid,
            amount_sats=plan.amount_at_step(2),
            blocks_remaining=self.block_delay,
            extra=vault.extra,
        )

    def complete_withdrawal(self, unvault: UnvaultState, path: str = "hot") -> TxRecord:
        """Complete withdrawal via hot path (after CSV) or cold path (recovery).

        CAT+CSFS vault paths:
            path="hot":  withdraw_tx — sends to destination after CSV timelock.
                         Uses hot key + CSFS introspection.
            path="cold": recover — immediate sweep to cold wallet (cold key only).

        For cross-covenant experiments: use path="hot" for normal withdrawal,
        and recover() for emergency recovery.
        """
        plan = unvault.extra["plan"]
        executor = unvault.extra["executor"]

        if path == "hot":
            # Mine enough blocks for CSV to pass
            self._cat_rpc.generatetoaddress(
                self.block_delay, self.fee_wallet.p2wpkh_address
            )
            withdraw_txid = executor.complete_withdrawal()
            label = "withdraw"
            amount = plan.amount_at_step(3)
        else:
            # Cold sweep from loop
            recover_txid = executor.recover(from_vault=False)
            self._cat_rpc.generatetoaddress(1, self.fee_wallet.p2wpkh_address)
            return TxRecord(
                txid=recover_txid,
                label="recover",
                raw_hex="",
                amount_sats=plan.amount_at_step(2) - plan.fees_per_step,
            )

        self._cat_rpc.generatetoaddress(1, self.fee_wallet.p2wpkh_address)

        tx = plan.sign_withdraw()
        return TxRecord(
            txid=withdraw_txid,
            label=label,
            raw_hex=tx.serialize().hex(),
            amount_sats=amount,
        )

    def recover(self, state) -> TxRecord:
        """Execute emergency recovery to cold wallet.

        CAT+CSFS recovery uses the cold key via OP_CHECKSIG in the recover
        leaf — no introspection needed, just a Schnorr signature.

        Works from both VaultState (recover from vault) and UnvaultState
        (recover from vault-loop).
        """
        plan = state.extra["plan"]
        executor = state.extra["executor"]

        if isinstance(state, VaultState):
            recover_txid = executor.recover(from_vault=True)
            source_amount = plan.amount_at_step(1)
        elif isinstance(state, UnvaultState):
            recover_txid = executor.recover(from_vault=False)
            source_amount = plan.amount_at_step(2)
        else:
            raise ValueError(f"Cannot recover from state type: {type(state)}")

        self._cat_rpc.generatetoaddress(1, self.fee_wallet.p2wpkh_address)

        recover_amount = source_amount - plan.fees_per_step
        return TxRecord(
            txid=recover_txid,
            label="recover",
            raw_hex="",
            amount_sats=recover_amount,
        )

    # ── Internals & Capabilities ────────────────────────────────────

    def get_internals(self) -> dict:
        return {
            "cat_rpc": self._cat_rpc,
            "cat_vault": self.cat_vault,
            "plan_class": self.cat_vault.VaultPlan,
            "executor_class": self.cat_vault.VaultExecutor,
            "fee_wallet": self.fee_wallet,
            "cold_wallet": self.cold_wallet,
            "hot_wallet": self.hot_wallet,
            "dest_wallet": self.dest_wallet,
            "pool": self._pool,
        }

    def supports_revault(self) -> bool:
        return False

    def supports_batched_trigger(self) -> bool:
        return False

    def supports_keyless_recovery(self) -> bool:
        return False  # Requires cold key signature

    # ── Metrics enrichment ───────────────────────────────────────────

    def collect_tx_metrics(self, record: TxRecord, rpc: RegTestRPC) -> TxMetrics:
        metrics = super().collect_tx_metrics(record, rpc)

        if record.label == "tovault":
            metrics.script_type = "p2wpkh_to_p2tr"
        elif record.label in ("trigger", "unvault"):
            metrics.script_type = "p2tr_cat_csfs"
        elif record.label == "withdraw":
            metrics.script_type = "p2tr_cat_csfs"
            metrics.csv_blocks = self.block_delay
        elif record.label == "recover":
            metrics.script_type = "p2tr_checksig"

        return metrics
