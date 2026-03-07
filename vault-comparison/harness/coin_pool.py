"""Shared coin pool for adapters that manage their own UTXO set.

Both CTV and CAT+CSFS adapters need to mine coinbases, split them into
exact amounts, and track change. This module extracts that logic so
it isn't duplicated across adapters.

Usage:
    pool = CoinPool(
        rpc=self._cat_rpc,
        bank_wallet=self._bank_wallet,
        vault_module=self.cat_vault,     # must expose Coin, txid_to_bytes
        scan_fn=scan_utxos,               # fn(rpc, address) -> dict
        generate_wallet=self.cat_vault.Wallet.generate,
        get_address=lambda w: w.p2wpkh_address,
        get_privkey=lambda w: w.privkey,
        mine_fn=lambda rpc, n, addr: rpc.generatetoaddress(n, addr),
        fee_address="bcrt1q...",          # address for mining blocks
    )
    coin, wallet = pool.fund(amount_sats=100_000)
"""
from dataclasses import dataclass, field
from typing import Callable, List, Tuple, Any, Optional


@dataclass
class CoinPool:
    """Manages a pool of split coins for vault funding.

    Parameters:
        rpc:              The upstream RPC client (any object with sendrawtransaction/generatetoaddress)
        bank_wallet:      Wallet object for holding coinbase UTXOs
        vault_module:     The upstream vault module (must expose Coin, txid_to_bytes)
        scan_fn:          Callable to scan UTXOs: fn(rpc, address) -> dict
        generate_wallet:  Factory to create new wallets: fn(seed) -> wallet
        get_address:      Get p2wpkh address from wallet: fn(wallet) -> str
        get_privkey:      Get privkey from wallet: fn(wallet) -> privkey
        mine_fn:          Mine blocks: fn(rpc, n, address) -> list
        fee_address:      Address for mining blocks during splits
    """
    rpc: Any
    bank_wallet: Any
    vault_module: Any
    scan_fn: Callable
    generate_wallet: Callable
    get_address: Callable
    get_privkey: Callable
    mine_fn: Callable
    fee_address: str

    _coins: List = field(default_factory=list, init=False)
    _initialized: bool = field(default=False, init=False)
    _counter: int = field(default=0, init=False)

    def unique_seed(self, base_seed: bytes) -> bytes:
        """Generate a unique seed for each split to avoid tx collisions."""
        self._counter += 1
        return base_seed + b"-vault-" + str(self._counter).encode()

    def ensure_bank(self):
        """Mine and mature a coinbase. Called lazily on first use."""
        if self._initialized:
            return
        self._initialized = True

        bank_addr = self.get_address(self.bank_wallet)
        self.mine_fn(self.rpc, 1, bank_addr)

        # Mature with 100 blocks to a throwaway address
        from buidl.hd import HDPrivateKey
        throwaway_addr = (
            HDPrivateKey.from_seed(b"throwaway-maturity")
            .get_private_key(1)
            .point.p2wpkh_address(network="regtest")
        )
        self.mine_fn(self.rpc, 100, throwaway_addr)

        self._scan_and_collect(bank_addr)

    def _scan_and_collect(self, address: str):
        """Scan for UTXOs at an address and add them to the pool."""
        from bitcoin.core import COutPoint, COIN
        Coin = self.vault_module.Coin
        txid_to_bytes = self.vault_module.txid_to_bytes

        scan = self.scan_fn(self.rpc, address)
        if scan["success"]:
            for utxo in scan["unspents"]:
                coin = Coin(
                    COutPoint(txid_to_bytes(utxo["txid"]), utxo["vout"]),
                    int(utxo["amount"] * COIN),
                    bytes.fromhex(utxo["scriptPubKey"]),
                    utxo.get("height", 0),
                )
                if coin not in self._coins:
                    self._coins.append(coin)

    def fund(self, amount_sats: int, seed: bytes = b"split") -> Tuple[Any, Any]:
        """Get a coin of the desired amount from the pool.

        Returns (coin, wallet) where coin has exactly amount_sats.
        """
        self.ensure_bank()
        result = self._try_split(amount_sats, seed)
        if result:
            return result

        # Mine a new coinbase and retry
        bank_addr = self.get_address(self.bank_wallet)
        self.mine_fn(self.rpc, 1, bank_addr)
        from buidl.hd import HDPrivateKey
        throwaway_addr = (
            HDPrivateKey.from_seed(b"throwaway-maturity-extra")
            .get_private_key(1)
            .point.p2wpkh_address(network="regtest")
        )
        self.mine_fn(self.rpc, 100, throwaway_addr)
        self._scan_and_collect(bank_addr)

        result = self._try_split(amount_sats, seed)
        if result:
            return result

        raise RuntimeError(
            f"Cannot fund {amount_sats} sats — bank coins: "
            f"{[c.amount for c in self._coins]}"
        )

    def _try_split(self, amount_sats: int, seed: bytes) -> Optional[Tuple[Any, Any]]:
        for i, coin in enumerate(self._coins):
            if coin.amount >= amount_sats + 1546:
                source = self._coins.pop(i)
                target, wallet, change = self._split_coin(
                    source, self.bank_wallet, amount_sats, seed
                )
                if change and change.amount > 10_000:
                    self._coins.append(change)
                return target, wallet
        return None

    def _split_coin(self, source_coin, source_wallet, amount_sats: int, seed: bytes):
        """Split a source coin into (target, change). Returns (target_coin, target_wallet, change_coin)."""
        from bitcoin.core import (
            CMutableTransaction, CTxIn, CTxOut, CTransaction,
            CTxInWitness, CScriptWitness, CTxWitness, COutPoint,
        )
        from bitcoin.core.script import CScript, OP_0
        from bitcoin.wallet import CBech32BitcoinAddress
        import bitcoin.core.script as script

        Coin = self.vault_module.Coin
        txid_to_bytes = self.vault_module.txid_to_bytes

        unique_seed = self.unique_seed(seed)
        target_wallet = self.generate_wallet(b"split-" + unique_seed)
        target_addr = self.get_address(target_wallet)
        target_h160 = CBech32BitcoinAddress(target_addr)
        target_script = CScript([OP_0, target_h160])

        source_addr = self.get_address(source_wallet)
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
        source_privkey = self.get_privkey(source_wallet)
        redeem_script = CScript([
            script.OP_DUP, script.OP_HASH160,
            CBech32BitcoinAddress(source_addr),
            script.OP_EQUALVERIFY, script.OP_CHECKSIG,
        ])
        sighash = script.SignatureHash(
            redeem_script, tx, 0, script.SIGHASH_ALL,
            amount=source_coin.amount, sigversion=script.SIGVERSION_WITNESS_V0,
        )
        sig = source_privkey.sign(int.from_bytes(sighash, "big")).der() + bytes([script.SIGHASH_ALL])
        tx.wit = CTxWitness([CTxInWitness(CScriptWitness([sig, source_privkey.point.sec()]))])

        split_tx = CTransaction.from_tx(tx)
        split_hex = split_tx.serialize().hex()
        split_txid = self.rpc.sendrawtransaction(split_hex)
        self.mine_fn(self.rpc, 1, self.fee_address)

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
