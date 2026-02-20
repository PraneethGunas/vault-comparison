"""CTV vault adapter.

Wraps simple-ctv-vault's VaultScenario / VaultPlan to expose the
uniform VaultAdapter interface. Requires a CTV-enabled regtest node
(Bitcoin Inquisition or Jeremy Rubin's fork).
"""

import sys
from pathlib import Path
from typing import Optional, List, Tuple

from adapters.base import VaultAdapter, VaultState, UnvaultState, TxRecord
from harness.rpc import RegTestRPC
from harness.metrics import TxMetrics

# Add simple-ctv-vault to the Python path so we can import its modules.
CTV_REPO = Path(__file__).resolve().parents[2] / "simple-ctv-vault"

# Counter for generating unique seeds per vault instance
_vault_counter = 0


def _ensure_ctv_imports():
    """Lazy-load the CTV vault modules."""
    if str(CTV_REPO) not in sys.path:
        sys.path.insert(0, str(CTV_REPO))

    from bitcoin import SelectParams
    SelectParams("regtest")

    import main as ctv_main
    import rpc as ctv_rpc
    return ctv_main, ctv_rpc


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
        self.ctv_main, self.ctv_rpc = _ensure_ctv_imports()

        self.fee_wallet = self.ctv_main.Wallet.generate(b"fee-" + seed)
        self.cold_wallet = self.ctv_main.Wallet.generate(b"cold-" + seed)
        self.hot_wallet = self.ctv_main.Wallet.generate(b"hot-" + seed)

        # We'll use ctv_rpc's BitcoinRPC for CTV-specific operations
        self._ctv_rpc = self.ctv_rpc.BitcoinRPC(net_name="regtest")

        # Coin pool: mine once, split many times.
        # Wallet.fund() mines 110 blocks per call — with regtest halving
        # every 150 blocks, that burns through subsidy fast.
        # Instead, we mine ONE coinbase + mature it, then split as needed.
        self._bank_wallet = self.ctv_main.Wallet.generate(b"bank-" + seed)
        self._bank_coins: list = []  # list of Coin objects available for splitting
        self._bank_initialized = False

    def _ensure_bank(self):
        """Mine a single coinbase and mature it. Called lazily on first use."""
        if self._bank_initialized:
            return
        self._bank_initialized = True

        # Mine one block to bank_wallet, then 100 blocks to a throwaway
        # address for maturity (total: 101 blocks, one coinbase)
        bank_addr = self._bank_wallet.privkey.point.p2wpkh_address(network="regtest")
        self._ctv_rpc.generatetoaddress(1, bank_addr)

        # Mine 100 more blocks to mature the coinbase (to throwaway addr)
        throwaway_addr = (
            self.ctv_main.HDPrivateKey.from_seed(b"throwaway-maturity")
            .get_private_key(1)
            .point.p2wpkh_address(network="regtest")
        )
        self._ctv_rpc.generatetoaddress(100, throwaway_addr)

        # Scan for the mature coinbase
        from main import scan_utxos, Coin, txid_to_bytes
        from bitcoin.core import COutPoint

        scan = scan_utxos(self._ctv_rpc, bank_addr)
        if scan["success"]:
            for utxo in scan["unspents"]:
                coin = Coin(
                    COutPoint(txid_to_bytes(utxo["txid"]), utxo["vout"]),
                    int(utxo["amount"] * 100_000_000),
                    bytes.fromhex(utxo["scriptPubKey"]),
                    utxo.get("height", 0),
                )
                self._bank_coins.append(coin)

    def _unique_seed(self) -> bytes:
        """Generate a unique seed for each vault to avoid tx collisions."""
        global _vault_counter
        _vault_counter += 1
        return self.seed + b"-vault-" + str(_vault_counter).encode()

    def _split_coin(self, source_coin, source_wallet, amount_sats: int):
        """Split a source coin, returning (target_coin, target_wallet, change_coin).

        The target_coin has exactly amount_sats.
        The change_coin (if any) goes back to source_wallet for reuse.
        """
        from bitcoin.core import (
            CMutableTransaction, CTxIn, CTxOut, CTransaction,
            CTxInWitness, CScriptWitness, CTxWitness, COutPoint,
        )
        from bitcoin.core.script import CScript, OP_0
        from bitcoin.wallet import CBech32BitcoinAddress
        import bitcoin.core.script as script
        from main import Coin, txid_to_bytes

        unique_seed = self._unique_seed()
        target_wallet = self.ctv_main.Wallet.generate(b"split-" + unique_seed)
        target_addr = target_wallet.privkey.point.p2wpkh_address(network="regtest")
        target_h160 = CBech32BitcoinAddress(target_addr)
        target_script = CScript([OP_0, target_h160])

        source_addr = source_wallet.privkey.point.p2wpkh_address(network="regtest")
        change_h160 = CBech32BitcoinAddress(source_addr)
        change_script = CScript([OP_0, change_h160])
        change_amount = source_coin.amount - amount_sats - 1000  # 1000 sat fee

        tx = CMutableTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(source_coin.outpoint, nSequence=0)]
        tx.vout = [CTxOut(amount_sats, target_script)]

        change_coin = None
        change_vout_idx = None
        if change_amount > 546:
            tx.vout.append(CTxOut(change_amount, change_script))
            change_vout_idx = 1

        # Sign (P2WPKH)
        redeem_script = CScript([
            script.OP_DUP, script.OP_HASH160,
            CBech32BitcoinAddress(source_addr),
            script.OP_EQUALVERIFY, script.OP_CHECKSIG,
        ])
        sighash = script.SignatureHash(
            redeem_script, tx, 0, script.SIGHASH_ALL,
            amount=source_coin.amount, sigversion=script.SIGVERSION_WITNESS_V0,
        )
        sig = source_wallet.privkey.sign(int.from_bytes(sighash, "big")).der() + bytes([script.SIGHASH_ALL])
        tx.wit = CTxWitness([CTxInWitness(CScriptWitness([sig, source_wallet.privkey.point.sec()]))])

        split_tx = CTransaction.from_tx(tx)
        split_hex = split_tx.serialize().hex()
        split_txid = self._ctv_rpc.sendrawtransaction(split_hex)
        self.ctv_main.generateblocks(self._ctv_rpc, 1)

        # Build target coin
        target_coin = Coin(
            COutPoint(txid_to_bytes(split_txid), 0),
            amount_sats,
            bytes(target_script),
            0,
        )

        # Build change coin for reuse
        if change_vout_idx is not None and change_amount > 546:
            change_coin = Coin(
                COutPoint(txid_to_bytes(split_txid), change_vout_idx),
                change_amount,
                bytes(change_script),
                0,
            )

        return target_coin, target_wallet, change_coin

    def _fund_coin(self, amount_sats: int):
        """Get a coin of the desired amount from the coin pool.

        Uses a single mined coinbase and splits it repeatedly, avoiding
        the 110-blocks-per-Wallet.fund() call that exhausts regtest subsidy.

        Returns (coin, wallet) where coin.amount == amount_sats.
        """
        self._ensure_bank()

        # Find a bank coin large enough
        for i, coin in enumerate(self._bank_coins):
            if coin.amount >= amount_sats + 1546:  # need room for fee + dust
                source_coin = self._bank_coins.pop(i)
                target_coin, target_wallet, change_coin = self._split_coin(
                    source_coin, self._bank_wallet, amount_sats
                )
                # Put change back into the pool
                if change_coin and change_coin.amount > 10_000:
                    self._bank_coins.append(change_coin)
                return target_coin, target_wallet

        # No coin large enough — need to mine a new coinbase
        # This should be rare after the initial bank setup
        bank_addr = self._bank_wallet.privkey.point.p2wpkh_address(network="regtest")
        self._ctv_rpc.generatetoaddress(1, bank_addr)

        throwaway_addr = (
            self.ctv_main.HDPrivateKey.from_seed(b"throwaway-maturity-extra")
            .get_private_key(1)
            .point.p2wpkh_address(network="regtest")
        )
        self._ctv_rpc.generatetoaddress(100, throwaway_addr)

        from main import scan_utxos, Coin, txid_to_bytes
        from bitcoin.core import COutPoint
        scan = scan_utxos(self._ctv_rpc, bank_addr)
        if scan["success"]:
            for utxo in scan["unspents"]:
                coin = Coin(
                    COutPoint(txid_to_bytes(utxo["txid"]), utxo["vout"]),
                    int(utxo["amount"] * 100_000_000),
                    bytes.fromhex(utxo["scriptPubKey"]),
                    utxo.get("height", 0),
                )
                if coin not in self._bank_coins:
                    self._bank_coins.append(coin)

        # Retry the split
        for i, coin in enumerate(self._bank_coins):
            if coin.amount >= amount_sats + 1546:
                source_coin = self._bank_coins.pop(i)
                target_coin, target_wallet, change_coin = self._split_coin(
                    source_coin, self._bank_wallet, amount_sats
                )
                if change_coin and change_coin.amount > 10_000:
                    self._bank_coins.append(change_coin)
                return target_coin, target_wallet

        raise RuntimeError(
            f"Cannot fund {amount_sats} sats — bank coins: "
            f"{[c.amount for c in self._bank_coins]}"
        )

    def create_vault(self, amount_sats: int) -> VaultState:
        """Fund a wallet, then create a vault of the specified amount."""
        coin, from_wallet = self._fund_coin(amount_sats)

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

        Args:
            path: "hot" (after timelock) or "cold" (immediate CTV sweep)
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

    # ── Capabilities ─────────────────────────────────────────────────

    def supports_revault(self) -> bool:
        return False

    def supports_batched_trigger(self) -> bool:
        return False

    def supports_keyless_recovery(self) -> bool:
        return False  # Cold sweep requires CTV witness, not a key, but not keyless in the CCV sense

    # ── Metrics enrichment ───────────────────────────────────────────

    def collect_tx_metrics(self, record: TxRecord, rpc: RegTestRPC) -> TxMetrics:
        metrics = super().collect_tx_metrics(record, rpc)

        # Annotate with CTV-specific script type info
        if record.label == "tovault":
            metrics.script_type = "bare_ctv"
        elif record.label in ("tohot", "tocold"):
            metrics.script_type = "p2wsh_ctv"
            metrics.csv_blocks = self.block_delay if record.label == "tohot" else 0
        elif record.label == "unvault":
            metrics.script_type = "bare_ctv"

        return metrics
