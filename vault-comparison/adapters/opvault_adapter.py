"""OP_VAULT (BIP-345) adapter.

Wraps jamesob/opvault-demo (the upstream reference implementation) to expose
the uniform VaultAdapter interface.  Requires jamesob's bitcoin-opvault node
(branch 2023-02-opvault-inq) on regtest.

The upstream repo uses the `verystable` library for script construction,
`bip32` for HD key derivation, and its own RPC layer (which supports
cookie-based auth natively).  Docker has been removed — we point
BITCOIN_RPC_URL at the local regtest node.
"""

import os
import sys
import hashlib
import json
import secrets
import tempfile
from pathlib import Path
from typing import Optional, List

from adapters.base import VaultAdapter, VaultState, UnvaultState, TxRecord
from harness.rpc import RegTestRPC
from harness.metrics import TxMetrics

# Path to the cloned opvault-demo repo (sibling to vault-comparison/)
OPVAULT_REPO = Path(__file__).resolve().parents[2] / "simple-op-vault"

# Counter for generating unique seeds per vault instance
_vault_counter = 0


def _ensure_opvault_imports():
    """Lazy-load the opvault-demo modules.

    Sets BITCOIN_RPC_URL to the local regtest node before importing,
    so that the upstream code talks to our switch-node-managed bitcoind
    rather than a Docker container.
    """
    # Point the upstream code at the local regtest node
    os.environ.setdefault("BITCOIN_RPC_URL", "http://127.0.0.1:18443")

    if str(OPVAULT_REPO) not in sys.path:
        sys.path.insert(0, str(OPVAULT_REPO))

    # verystable must activate the softfork flags before any script work
    import verystable
    import verystable.core.messages as _msgs

    # ── Monkey-patch: verystable 28.1.0-dev renamed CTransaction.nVersion
    # to .version, but softforks._get_standard_template_hash still
    # references self.nVersion.  Add a compatibility property so both work.
    _CTx = _msgs.CTransaction
    if not hasattr(_CTx, "nVersion"):
        _CTx.nVersion = property(lambda self: self.version)
    # CMutableTransaction may not exist in all verystable versions
    _MTx = getattr(_msgs, "CMutableTransaction", None)
    if _MTx is not None and not hasattr(_MTx, "nVersion"):
        _MTx.nVersion = property(lambda self: self.version)

    # ── Monkey-patch: upstream main.py passes `script=` kwarg to
    # TaprootSignatureHash, but verystable 28.1.0-dev renamed
    # it to `leaf_script=`.  Wrap to accept both.
    import verystable.core.script as _script
    _orig_sig_msg = _script.TaprootSignatureMsg

    def _patched_sig_msg(*args, **kwargs):
        if "script" in kwargs and "leaf_script" not in kwargs:
            kwargs["leaf_script"] = kwargs.pop("script")
        return _orig_sig_msg(*args, **kwargs)

    _script.TaprootSignatureMsg = _patched_sig_msg

    verystable.softforks.activate_bip345_vault()
    verystable.softforks.activate_bip119_ctv()

    import main as opvault_main
    return opvault_main


class OPVaultAdapter(VaultAdapter):

    @property
    def name(self) -> str:
        return "opvault"

    @property
    def node_mode(self) -> str:
        return "opvault"

    @property
    def description(self) -> str:
        return "OP_VAULT vault (BIP 345 + BIP 119) via jamesob/opvault-demo"

    def setup(self, rpc: RegTestRPC, block_delay: int = 10,
              seed: bytes = b"compare", **kwargs) -> None:
        self.rpc = rpc
        self.block_delay = block_delay
        self.seed = seed
        self.ov = _ensure_opvault_imports()

        # The upstream RPC (verystable.rpc.BitcoinRPC) — supports cookie auth
        from verystable.rpc import BitcoinRPC
        self._ov_rpc = BitcoinRPC(
            net_name="regtest",
            service_url=os.environ.get("BITCOIN_RPC_URL", "http://127.0.0.1:18443"),
        )

        # Fee wallet used by the upstream code for paying tx fees
        # SingleAddressWallet requires exactly 32 bytes for ECKey.set()
        from verystable.wallet import SingleAddressWallet
        fee_seed = hashlib.sha256(seed + b"-fees").digest()
        self._fee_wallet = SingleAddressWallet(
            self._ov_rpc, locked_utxos=set(), seed=fee_seed
        )

        # Working directory for config/secrets files (per-session temp dir)
        self._workdir = Path(tempfile.mkdtemp(prefix="opvault_"))

        # Pre-fund the fee wallet: mine blocks to its address, mature them
        self._fund_fee_wallet()

    # ------------------------------------------------------------------
    # Fee wallet funding
    # ------------------------------------------------------------------

    def _fund_fee_wallet(self):
        """Mine coins to the fee wallet so triggers/recoveries can pay fees."""
        fee_addr = self._fee_wallet.fee_addr
        # Mine a few coinbases to the fee wallet
        self._ov_rpc.generatetoaddress(5, fee_addr)
        # Mature them
        dummy = self._ov_rpc.getnewaddress() if self._has_default_wallet() else fee_addr
        self._ov_rpc.generatetoaddress(100, fee_addr)
        # Rescan so the fee wallet sees its UTXOs
        self._fee_wallet.rescan()

    def _has_default_wallet(self) -> bool:
        """Check if there's a default wallet loaded."""
        try:
            self._ov_rpc.getwalletinfo()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Config generation (replaces createconfig.py)
    # ------------------------------------------------------------------

    def _create_config(self, vault_seed: bytes = None) -> "WalletMetadata":
        """Programmatically create a vault config (like createconfig.py).

        Returns a WalletMetadata object ready for use.
        """
        from bip32 import BIP32

        vault_seed = vault_seed or secrets.token_bytes(32)
        # BIP32.from_seed() requires 16-64 bytes
        trig_seed = hashlib.sha256(vault_seed + b"-trigger").digest()
        trig32 = BIP32.from_seed(trig_seed)
        recovery_seed = hashlib.sha256(vault_seed + b"-recovery").digest()
        recovery32 = BIP32.from_seed(recovery_seed)
        recovery_pubkey = recovery32.get_pubkey_from_path("m/0h/0")[1:]  # x-only

        recoveryauth_key = self.ov.recoveryauth_phrase_to_key("changeme2")
        recoveryauth_pubkey = recoveryauth_key.get_pubkey().get_bytes()[1:]  # x-only

        config = self.ov.VaultConfig(
            spend_delay=self.block_delay,
            recovery_pubkey=recovery_pubkey,
            recoveryauth_pubkey=recoveryauth_pubkey,
            trigger_xpub=trig32.get_xpub(),
            birthday_height=0,
        )

        # Save config to temp file (required by upstream load())
        config_path = self._workdir / f"config-{_vault_counter}.json"
        metadata = self.ov.WalletMetadata(
            config,
            filepath=config_path,
            fee_wallet_seed=hashlib.sha256(self.seed + b"-fees").digest(),
        )
        metadata.save()

        # Save secrets
        secrets_path = self._workdir / f"secrets-{_vault_counter}.json"
        secd = {
            config.id: {
                'trigger_xpriv': trig32.get_xpriv(),
                'recoveryauth_phrase': 'changeme2',
            }
        }
        secrets_path.write_text(json.dumps(secd, indent=2))
        config.secrets_filepath = secrets_path

        return metadata

    # ------------------------------------------------------------------
    # Core vault lifecycle
    # ------------------------------------------------------------------

    def create_vault(self, amount_sats: int) -> VaultState:
        """Deposit funds into an OP_VAULT vault.

        Creates a fresh config, mines coins to the vault deposit address,
        then returns a VaultState handle.
        """
        global _vault_counter
        _vault_counter += 1

        vault_seed = self.seed + f"-vault-{_vault_counter}".encode()
        metadata = self._create_config(vault_seed)
        config = metadata.config

        # Get the first deposit address
        vault_spec = config.get_spec_for_vault_num(0)
        deposit_addr = vault_spec.address

        # Fund the vault: send coins to the deposit address
        # Mine a coinbase, mature it, then send to vault
        fee_addr = self._fee_wallet.fee_addr
        self._ov_rpc.generatetoaddress(1, fee_addr)
        self._ov_rpc.generatetoaddress(100, fee_addr)
        self._fee_wallet.rescan()

        # Use the fee wallet to send to the vault address
        # We'll use bitcoin-cli style sendtoaddress via raw tx construction
        deposit_txid = self._send_to_address(deposit_addr, amount_sats)

        # Mine to confirm
        self._ov_rpc.generatetoaddress(1, fee_addr)

        # Build the chain monitor and rescan to pick up the deposit
        monitor = self.ov.ChainMonitor(metadata, self._ov_rpc)
        state = monitor.rescan()

        return VaultState(
            vault_txid=deposit_txid,
            amount_sats=amount_sats,
            vault_address=deposit_addr,
            extra={
                "metadata": metadata,
                "config": config,
                "monitor": monitor,
                "chain_state": state,
                "vault_spec": vault_spec,
                "vault_seed": vault_seed,
            },
        )

    def _send_to_address(self, address: str, amount_sats: int) -> str:
        """Send amount_sats to address using the fee wallet.

        Constructs a raw transaction spending from the fee wallet.
        """
        from verystable.core import messages, address as addr_mod
        from verystable.core.script import CScript
        from verystable.core.messages import COutPoint, CTxOut, CTxIn
        from verystable.script import CTransaction
        from verystable import core

        self._fee_wallet.rescan()
        fee_utxo = self._fee_wallet.get_utxo()

        dest_spk = addr_mod.address_to_scriptpubkey(address)
        change = fee_utxo.value_sats - amount_sats - self.ov.FEE_VALUE_SATS
        assert change > 0, (
            f"Fee UTXO ({fee_utxo.value_sats}) too small for "
            f"{amount_sats} + {self.ov.FEE_VALUE_SATS} fee"
        )

        tx = CTransaction()
        tx.version = 2
        tx.vin = [fee_utxo.as_txin]
        tx.vout = [
            CTxOut(nValue=amount_sats, scriptPubKey=dest_spk),
            CTxOut(nValue=change, scriptPubKey=self._fee_wallet.fee_spk),
        ]

        spent_outputs = [fee_utxo.output]
        from verystable.core.script import TaprootSignatureHash
        sigmsg = TaprootSignatureHash(
            tx, spent_outputs, input_index=0, hash_type=0)

        wit = messages.CTxInWitness()
        tx.wit.vtxinwit = [wit]
        wit.scriptWitness.stack = [self._fee_wallet.sign_msg(sigmsg)]

        txid = self._ov_rpc.sendrawtransaction(tx.tohex())
        return txid

    def trigger_unvault(self, vault: VaultState) -> UnvaultState:
        """Trigger a withdrawal from the vault.

        Uses start_withdrawal() from the upstream code to build the
        trigger + final-withdrawal transaction pair.
        """
        metadata = vault.extra["metadata"]
        config = vault.extra["config"]
        chain_state = vault.extra["chain_state"]
        monitor = vault.extra["monitor"]

        # Pick a destination address (use fee wallet as a simple hot target)
        # start_withdrawal() reserves FEE_VALUE_SATS for the final withdrawal tx
        # and requires the destination amount < total vault value - fees.
        # We withdraw as much as possible while leaving room for the fee budget.
        fee_addr = self._fee_wallet.fee_addr
        withdraw_sats = vault.amount_sats - 2 * self.ov.FEE_VALUE_SATS
        assert withdraw_sats > 0, (
            f"Vault balance ({vault.amount_sats}) too small for fees "
            f"({2 * self.ov.FEE_VALUE_SATS})"
        )
        dest = self.ov.PaymentDestination(fee_addr, withdraw_sats)

        # Get available vault UTXOs from the chain state
        chain_state = monitor.rescan()
        vault_utxos = list(chain_state.vault_utxos.values())
        assert vault_utxos, "No vault UTXOs found after rescan"

        # Coin selection: start_withdrawal() requires that at most 2 UTXOs
        # are passed (one covers the destination, one optional excess for
        # revault).  Pick the single UTXO matching our deposit txid, or
        # if not identifiable, just the one closest in value.
        target_txid = vault.vault_txid
        matching = [u for u in vault_utxos
                    if hasattr(u, "outpoint") and target_txid in str(u.outpoint)]
        if matching:
            vault_utxos = matching[:1]
        else:
            # Fallback: pick the single UTXO whose value is closest to our deposit
            vault_utxos = [min(vault_utxos,
                               key=lambda u: abs(u.value_sats - vault.amount_sats))]

        # Load the trigger signing key from secrets
        secd = json.loads(config.secrets_filepath.read_text())[config.id]
        from bip32 import BIP32
        trig_b32 = BIP32.from_xpriv(secd['trigger_xpriv'])
        from verystable import core

        def trigger_key_signer(msg: bytes, vault_num: int) -> bytes:
            privkey = trig_b32.get_privkey_from_path(
                f"{config.trigger_xpub_path_prefix}/{vault_num}")
            return core.key.sign_schnorr(privkey, msg)

        # Refresh fee wallet
        self._fee_wallet.rescan()

        # Build trigger spec
        trigger_spec = self.ov.start_withdrawal(
            config, self._fee_wallet, vault_utxos, dest, trigger_key_signer
        )

        # Register with metadata so monitor recognizes it
        metadata.triggers[trigger_spec.id] = trigger_spec
        metadata.save()

        # Broadcast the trigger transaction
        assert trigger_spec.trigger_tx
        try:
            self._ov_rpc.sendrawtransaction(trigger_spec.trigger_tx.tohex())
        except Exception as e:
            if "-27" not in str(e):  # already in blockchain
                raise

        # Mine to confirm
        self._ov_rpc.generatetoaddress(1, self._fee_wallet.fee_addr)

        return UnvaultState(
            unvault_txid=trigger_spec.trigger_tx.rehash(),
            amount_sats=withdraw_sats,
            blocks_remaining=self.block_delay,
            extra={
                **vault.extra,
                "trigger_spec": trigger_spec,
                "chain_state": monitor.rescan(),
            },
        )

    def complete_withdrawal(self, unvault: UnvaultState, path: str = "hot") -> TxRecord:
        """Complete the withdrawal after the spend delay.

        Hot path: mine spend_delay blocks, then broadcast the CTV-locked
                  final withdrawal transaction.
        Cold path: broadcast recovery transaction (immediate, no delay).
        """
        trigger_spec = unvault.extra["trigger_spec"]
        config = unvault.extra["config"]
        metadata = unvault.extra["metadata"]
        monitor = unvault.extra["monitor"]

        if path == "hot":
            # Mine blocks to satisfy spend_delay
            self._ov_rpc.generatetoaddress(
                self.block_delay, self._fee_wallet.fee_addr)

            # Broadcast the final withdrawal tx (CTV template)
            assert trigger_spec.withdrawal_tx
            try:
                self._ov_rpc.sendrawtransaction(trigger_spec.withdrawal_tx.tohex())
            except Exception as e:
                if "-27" not in str(e):
                    raise

            # Mine to confirm
            self._ov_rpc.generatetoaddress(1, self._fee_wallet.fee_addr)

            return TxRecord(
                txid=trigger_spec.withdrawal_tx.rehash(),
                label="withdraw",
                amount_sats=unvault.amount_sats,
            )
        else:
            # Cold recovery: recover the triggered UTXO
            return self._do_recovery(unvault, from_vault=False)

    def recover(self, state) -> TxRecord:
        """Execute emergency recovery from vault or triggered state."""
        from_vault = isinstance(state, VaultState)
        return self._do_recovery(state, from_vault=from_vault)

    def _do_recovery(self, state, from_vault: bool = True) -> TxRecord:
        """Recover funds to the recovery address.

        Uses get_recovery_tx() from the upstream code.
        """
        config = state.extra["config"]
        monitor = state.extra["monitor"]

        # Rescan to get current UTXO state
        chain_state = monitor.rescan()

        if from_vault:
            utxos = list(chain_state.vault_utxos.values())
        else:
            utxos = list(chain_state.trigger_utxos.values())
            # Also include theft triggers
            utxos.extend(chain_state.theft_trigger_utxos.keys())

        assert utxos, f"No {'vault' if from_vault else 'trigger'} UTXOs to recover"

        # Load recovery auth key
        secd = json.loads(config.secrets_filepath.read_text())[config.id]
        recovery_privkey = self.ov.recoveryauth_phrase_to_key(
            secd['recoveryauth_phrase']).get_bytes()

        from verystable import core

        def recoveryauth_signer(msg: bytes) -> bytes:
            return core.key.sign_schnorr(recovery_privkey, msg)

        # Refresh fee wallet
        self._fee_wallet.rescan()

        recovery_spec = self.ov.get_recovery_tx(
            config, self._fee_wallet, utxos, recoveryauth_signer
        )

        self._ov_rpc.sendrawtransaction(recovery_spec.tx.tohex())

        # Mine to confirm
        self._ov_rpc.generatetoaddress(1, self._fee_wallet.fee_addr)

        return TxRecord(
            txid=recovery_spec.tx.rehash(),
            label="recover",
            amount_sats=state.amount_sats,
        )

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    def supports_revault(self) -> bool:
        """OP_VAULT supports partial withdrawal with revault.

        The start_withdrawal() function automatically creates a revault
        output when the vault UTXOs exceed the destination amount.
        """
        return True

    def supports_batched_trigger(self) -> bool:
        """OP_VAULT supports batching multiple vault UTXOs in one trigger.

        The start_withdrawal() function accepts a list of VaultUtxo objects,
        combining them into a single trigger transaction.
        """
        return True

    def supports_keyless_recovery(self) -> bool:
        """OP_VAULT uses authorized recovery (recoveryauth key required).

        BIP-345 supports both modes, but the default configuration requires
        a recoveryauth signature to prevent fee-griefing of recovery txns.
        """
        return False

    # ------------------------------------------------------------------
    # Metrics collection
    # ------------------------------------------------------------------

    def collect_tx_metrics(self, record: TxRecord, rpc: RegTestRPC) -> TxMetrics:
        """Build TxMetrics from a broadcast transaction."""
        info = rpc.get_tx_info(record.txid)
        fee = rpc.get_tx_fee_sats(record.txid)

        script_type_map = {
            "tovault": "p2tr_opvault",
            "trigger": "p2tr_opvault",
            "withdraw": "p2tr_ctv",
            "tocold": "p2tr_opvault_recover",
            "recover": "p2tr_opvault_recover",
        }
        script_type = script_type_map.get(record.label, "p2tr")

        return TxMetrics(
            label=record.label,
            txid=record.txid,
            vsize=info["vsize"],
            weight=info["weight"],
            fee_sats=fee,
            num_inputs=len(info["vin"]),
            num_outputs=len(info["vout"]),
            amount_sats=record.amount_sats,
            script_type=script_type,
        )

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def teardown(self) -> None:
        """Remove temporary config/secret files."""
        import shutil
        if hasattr(self, '_workdir') and self._workdir.exists():
            shutil.rmtree(self._workdir, ignore_errors=True)
