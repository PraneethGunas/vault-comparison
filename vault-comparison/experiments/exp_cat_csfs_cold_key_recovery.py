"""Experiment: CAT+CSFS Cold Key Recovery — No-Covenant Recovery Path

Analyzes the security properties and attack surface of the CAT+CSFS
vault's recovery mechanism.  Unlike the trigger/withdraw paths that use
CSFS+CHECKSIG introspection, recovery uses a simple OP_CHECKSIG with the
cold key.  There is NO covenant enforcement on the recovery output.

=== ARCHITECTURE ===
Recovery leaf script: cold_pk_xonly OP_CHECKSIG

That's it.  No CAT, no CSFS, no amount checking, no output constraints.
The cold key can send the vault funds to ANY address.

This is by design: recovery is the escape hatch.  But it means cold key
compromise is catastrophic — the attacker can immediately sweep to any
address with no timelock, no watchtower defense, and no covenant
protection.

=== RELATED WORK ===
All four vault designs have single-point-of-failure cold/recovery keys:
  - CTV: Cold key controls tocold destination (pre-committed but
    cold key holder controls the destination wallet)
  - CCV: Recovery is KEYLESS — anyone can trigger, goes to pre-committed
    recovery address (controlled by recovery wallet)
  - OP_VAULT: Recovery requires recoveryauth key, goes to pre-committed
    recovery address.  Recovery address is encoded as a scriptPubKey
    hash in the OP_VAULT output — immutable.
  - CAT+CSFS: Recovery requires cold key, goes to cold wallet (P2WPKH).
    No destination constraint — cold key holder signs SIGHASH_DEFAULT
    which commits to the actual output, not an embedded one.

=== THREAT MODEL: Cold key compromise ===
Attacker: Has the cold key.  Goal: steal all vault funds immediately.
Severity: CRITICAL for all vault designs.
CAT+CSFS specific: The attacker broadcasts sign_recover() with a
  modified output (attacker address).  Since the recover leaf is just
  OP_CHECKSIG with SIGHASH_DEFAULT, the cold key holder controls where
  funds go.  Wait — actually, the VaultPlan computes the recovery output
  at construction time (cold wallet address).  But an attacker with the
  cold PRIVATE KEY can construct a completely new recovery transaction
  spending the vault UTXO to any address.

Key difference: CCV's recovery goes to a pre-committed address even
without a key.  OP_VAULT's recovery goes to a pre-committed address
(enforced by the opcode).  CAT+CSFS's recovery goes wherever the cold
key signs for — the vault script doesn't constrain the recovery output.

=== EMPIRICAL DEMONSTRATION ===
Phase 1: Normal recovery — verify the happy path.
Phase 2: Attacker recovery — construct a recovery tx that sends funds
  to an attacker-controlled address using the cold key.  Expected:
  ACCEPTED — the recover leaf is just OP_CHECKSIG.
Phase 3: Recovery timing analysis — measure the cold key's power:
  can recover from vault state (before trigger) and vault-loop state
  (after trigger).  No timelock on either.
Phase 4: Cross-vault recovery security comparison.
"""

import sys
from pathlib import Path

from adapters.base import VaultAdapter, VaultState, UnvaultState, TxRecord
from harness.metrics import ExperimentResult, TxMetrics
from harness.regtest_caveats import emit_regtest_caveats
from experiments.registry import register


VAULT_AMOUNT = 49_999_900


@register(
    name="cat_csfs_cold_key_recovery",
    description="CAT+CSFS cold key recovery: no-covenant recovery path and cold key compromise",
    tags=["cat_csfs_only", "security", "critical"],
    required_covenants=["cat_csfs"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    result = ExperimentResult(
        experiment="cat_csfs_cold_key_recovery",
        covenant=adapter.name,
        params={"vault_amount_sats": VAULT_AMOUNT},
    )

    if adapter.name != "cat_csfs":
        result.observe("Skipping — CAT+CSFS-specific experiment.")
        return result

    try:
        _run_cold_key_recovery(adapter, result)
    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")
        import traceback
        result.observe(traceback.format_exc())

    emit_regtest_caveats(
        result,
        experiment_specific=(
            "Recovery is a consensus-level operation — the OP_CHECKSIG "
            "validation in the recover leaf is identical on regtest and "
            "mainnet.  The cold key redirection test (Phase 2) demonstrates "
            "a real vulnerability: any holder of the cold private key can "
            "redirect vault funds.  This is inherent to the OP_CHECKSIG "
            "recovery design and not a regtest artifact."
        ),
    )

    return result


def _run_cold_key_recovery(adapter, result):
    """Run the cold key recovery analysis."""
    CAT_CSFS_REPO = Path(__file__).resolve().parents[2] / "simple-cat-csfs-vault"
    repo_str = str(CAT_CSFS_REPO)
    if repo_str not in sys.path:
        sys.path.insert(0, repo_str)

    from bitcoin.core import (
        CMutableTransaction, CTxIn, CTxOut, CTransaction,
        CTxInWitness, CScriptWitness, CTxWitness, COutPoint,
    )
    from bitcoin.core.script import CScript
    from vault import VaultPlan, Wallet, txid_to_bytes
    from taproot import (
        NUMS_POINT_X, LEAF_VERSION_TAPSCRIPT,
        build_control_block, tapleaf_hash,
        compute_tapscript_sighash, schnorr_sign,
    )

    cat_rpc = adapter._cat_rpc
    rpc = adapter.rpc

    # ── Phase 1: Normal recovery ──────────────────────────────────────
    result.observe("=" * 60)
    result.observe("PHASE 1: Normal recovery (happy path)")
    result.observe("=" * 60)

    vault = adapter.create_vault(VAULT_AMOUNT)
    plan = vault.extra["plan"]
    result.observe(f"Vault created: {vault.vault_txid[:16]}... ({vault.amount_sats} sats)")
    result.observe(f"Cold wallet: {adapter.cold_wallet.p2wpkh_address}")

    # Recovery from vault state
    recover_record = adapter.recover(vault)
    recover_info = rpc.get_tx_info(recover_record.txid)
    recover_vsize = recover_info["vsize"]
    result.observe(f"Recovery from vault: {recover_record.txid[:16]}... ({recover_vsize} vB)")

    # Verify funds went to cold wallet
    recover_output = recover_info["vout"][0]
    recover_addr = recover_output.get("scriptPubKey", {}).get("address", "")
    recover_amount = int(recover_output["value"] * 100_000_000)
    result.observe(f"Recovery output: {recover_amount} sats → {recover_addr}")

    if recover_addr == adapter.cold_wallet.p2wpkh_address:
        result.observe("CONFIRMED: Funds recovered to cold wallet.")
    else:
        result.observe(f"WARNING: Recovery went to unexpected address: {recover_addr}")

    result.add_tx(TxMetrics(
        label="normal_recovery_from_vault",
        txid=recover_record.txid,
        vsize=recover_vsize,
        weight=recover_info.get("weight", 0),
        amount_sats=recover_amount,
        script_type="p2tr_checksig",
    ))

    # Recovery from vault-loop state
    vault2 = adapter.create_vault(VAULT_AMOUNT)
    unvault2 = adapter.trigger_unvault(vault2)
    recover2 = adapter.recover(unvault2)
    recover2_info = rpc.get_tx_info(recover2.txid)
    recover2_vsize = recover2_info["vsize"]
    result.observe(f"Recovery from vault-loop: {recover2.txid[:16]}... ({recover2_vsize} vB)")

    result.add_tx(TxMetrics(
        label="normal_recovery_from_loop",
        txid=recover2.txid,
        vsize=recover2_vsize,
        weight=recover2_info.get("weight", 0),
        amount_sats=recover2.amount_sats,
        script_type="p2tr_checksig",
    ))

    # ── Phase 2: Attacker recovery (cold key redirects funds) ─────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 2: Cold key compromise — attacker redirects recovery")
    result.observe("=" * 60)

    vault3 = adapter.create_vault(VAULT_AMOUNT)
    plan3 = vault3.extra["plan"]
    result.observe(f"Vault created: {vault3.vault_txid[:16]}...")

    # Build a recovery tx that sends to an ATTACKER address
    attacker_wallet = Wallet.generate(b"cold-key-attacker")
    attacker_spk = attacker_wallet.p2wpkh_script_pubkey

    vault_txid_bytes = txid_to_bytes(vault3.vault_txid)
    source_amount = plan3.amount_at_step(1)
    recover_amount = source_amount - plan3.fees_per_step

    attacker_tx = CMutableTransaction()
    attacker_tx.nVersion = 2
    attacker_tx.vin = [CTxIn(COutPoint(vault_txid_bytes, 0), nSequence=0)]
    attacker_tx.vout = [CTxOut(recover_amount, CScript(attacker_spk))]

    # Sign with the cold key (which the attacker has)
    recover_script = plan3.vault_recover_script
    tl_hash = tapleaf_hash(recover_script)

    sighash = compute_tapscript_sighash(
        tx=CTransaction.from_tx(attacker_tx),
        input_index=0,
        prevouts=[(vault_txid_bytes, 0)],
        amounts=[source_amount],
        scriptpubkeys=[plan3.vault_spk],
        tapleaf_hash_val=tl_hash,
        hash_type=0x00,  # SIGHASH_DEFAULT — signs everything
    )

    sig = schnorr_sign(adapter.cold_wallet.secret, sighash)

    control_block = build_control_block(
        NUMS_POINT_X,
        LEAF_VERSION_TAPSCRIPT,
        plan3.vault_output_parity,
        [plan3.vault_trigger_hash],
    )

    witness_items = [
        sig,                    # for OP_CHECKSIG
        recover_script,         # tapscript
        control_block,          # control block
    ]

    attacker_tx.wit = CTxWitness([
        CTxInWitness(CScriptWitness(witness_items))
    ])

    attacker_hex = CTransaction.from_tx(attacker_tx).serialize().hex()

    result.observe(f"Attacker address: {attacker_wallet.p2wpkh_address}")
    result.observe("Broadcasting recovery to attacker address...")

    try:
        txid = cat_rpc.sendrawtransaction(attacker_hex)
        cat_rpc.generatetoaddress(1, adapter.fee_wallet.p2wpkh_address)

        tx_info = cat_rpc.getrawtransaction(txid, True)
        actual_addr = tx_info["vout"][0]["scriptPubKey"].get("address", "")
        theft_amount = int(tx_info["vout"][0]["value"] * 100_000_000)

        result.observe(f"ACCEPTED: {txid[:16]}...")
        result.observe(f"Funds redirected: {theft_amount} sats → {actual_addr}")

        if actual_addr == attacker_wallet.p2wpkh_address:
            result.observe(
                "CONFIRMED: Cold key holder can redirect recovery funds to "
                "ANY address.  The recover leaf (cold_pk OP_CHECKSIG) has "
                "NO covenant constraint on the output.  SIGHASH_DEFAULT "
                "commits to the actual output, so the cold key holder "
                "controls the destination."
            )
        else:
            result.observe(f"Output went to: {actual_addr} (expected attacker)")

        result.add_tx(TxMetrics(
            label="attacker_recovery",
            txid=txid,
            vsize=tx_info.get("vsize", 0),
            weight=tx_info.get("weight", 0),
            amount_sats=theft_amount,
            script_type="p2tr_checksig_redirected",
        ))

    except Exception as e:
        err_str = str(e)
        result.observe(f"REJECTED: {err_str[:200]}")
        result.observe(
            "UNEXPECTED: Cold key recovery with attacker output was rejected.  "
            "This contradicts the expected behavior of OP_CHECKSIG."
        )
        result.error = f"Cold key redirection rejected: {err_str[:100]}"

    # ── Phase 3: Recovery timing analysis ─────────────────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 3: Recovery timing — no timelock on recovery")
    result.observe("=" * 60)

    result.observe(
        "The recover leaf has NO OP_CHECKSEQUENCEVERIFY.  The cold key "
        "can sweep funds IMMEDIATELY from either vault or vault-loop state."
    )
    result.observe(
        "  Recovery from vault: No trigger needed.  Cold key directly "
        "spends the vault UTXO.  Fastest possible theft."
    )
    result.observe(
        "  Recovery from vault-loop: Cold key spends the vault-loop UTXO "
        "during the CSV delay.  Beats the hot key withdrawal."
    )
    result.observe(
        f"  Vault recovery vsize: {recover_vsize} vB"
    )
    result.observe(
        f"  Loop recovery vsize: {recover2_vsize} vB"
    )
    result.observe(
        "  Both are lightweight: simple OP_CHECKSIG witness (sig + script + "
        "control block).  No CSFS overhead, no preimage splitting."
    )

    # Timing analysis
    result.observe("")
    result.observe("DEFENSE ANALYSIS: What protects against cold key theft?")
    result.observe(
        "  NOTHING in the vault protocol.  Cold key compromise = immediate "
        "total fund loss.  No timelock, no watchtower, no recovery from "
        "recovery."
    )
    result.observe(
        "  External defenses only:"
    )
    result.observe(
        "    - Multisig cold key (requires protocol change or taproot MuSig)"
    )
    result.observe(
        "    - Hardware security module (HSM) for cold key"
    )
    result.observe(
        "    - Shamir's Secret Sharing for cold key backup"
    )
    result.observe(
        "    - Geographic distribution of cold key material"
    )

    # ── Phase 4: Cross-vault recovery comparison ──────────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 4: Recovery security comparison")
    result.observe("=" * 60)
    result.observe(
        "  CTV:      Recovery = tocold_tx (pre-committed CTV template).  "
        "Cold key holder controls the destination wallet, but the "
        "tocold transaction itself is CTV-locked to a specific output.  "
        "Cold key compromise: attacker controls destination wallet."
    )
    result.observe(
        "  CCV:      Recovery = KEYLESS (anyone can trigger).  Goes to "
        "pre-committed recovery address enforced by CCV.  "
        "No key compromise possible for recovery itself.  "
        "Recovery wallet compromise: attacker controls destination."
    )
    result.observe(
        "  OP_VAULT: Recovery = recoveryauth key + OP_VAULT_RECOVER.  "
        "Goes to pre-committed recovery address (SPK hash in output).  "
        "Recoveryauth key compromise: can grief (trigger recovery) but "
        "funds go to pre-committed address.  Recovery address is safe."
    )
    result.observe(
        "  CAT+CSFS: Recovery = cold key OP_CHECKSIG.  No output constraint.  "
        "Cold key compromise: IMMEDIATE TOTAL THEFT to any address.  "
        "No pre-committed recovery address.  No defense."
    )
    result.observe(
        "  RECOVERY SECURITY RANKING:"
    )
    result.observe(
        "    1. CCV (keyless recovery, pre-committed destination — "
        "no single key can redirect)"
    )
    result.observe(
        "    2. OP_VAULT (recoveryauth key, pre-committed destination — "
        "key compromise = grief, not theft)"
    )
    result.observe(
        "    3. CTV (CTV-locked tocold, destination wallet holds funds — "
        "wallet key compromise = theft of recovered funds)"
    )
    result.observe(
        "    4. CAT+CSFS (cold key OP_CHECKSIG, no destination constraint — "
        "cold key compromise = IMMEDIATE DIRECT THEFT)"
    )
    result.observe(
        "  DESIGN INSIGHT: The simplicity of the recover leaf (cold_pk "
        "OP_CHECKSIG) is both a strength and a weakness.  It's the simplest "
        "possible recovery mechanism — no complex script to audit, no "
        "risk of logic bugs.  But it offers NO protocol-level protection "
        "against cold key compromise.  The tradeoff: implementation "
        "simplicity vs recovery security depth."
    )
