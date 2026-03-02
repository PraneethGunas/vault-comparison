"""Experiment: CAT+CSFS Destination Lock — Inflexible Withdrawal Target

Analyzes the CAT+CSFS vault's unique property: the withdrawal destination
is LOCKED at vault creation time, embedded as sha_single_output in the
withdraw leaf script.  This contrasts with OP_VAULT (destination chosen
at trigger time) and CCV (destination chosen at trigger time via CTV
hash in the augmented state).

=== RELATED WORK ===
BIP 345 (OP_VAULT) §start_withdrawal specifies that the trigger key
holder commits to a CTV template at trigger time, allowing flexible
destination selection.  CCV/MATT (BIP 443) uses augmented state to embed
the CTV hash, also committed at trigger time.

The CTV vault (BIP 119) has a similar destination-lock property: the
tohot and tocold templates are baked in at vault creation.  But CTV's
two-path design (hot + cold) provides some flexibility — different
pre-committed destinations for normal withdrawal vs emergency.

CAT+CSFS has the strictest lock: a SINGLE pre-committed destination
for withdrawal, with recovery going to the cold wallet.

=== THREAT MODEL: Destination lock implications ===
Scenario 1 — Key rotation:
  If the destination wallet's keys are compromised or rotated, the vault
  funds cannot be redirected to the new wallet via the withdrawal path.
  The vault must be recovered to cold storage and re-vaulted with a new
  destination.  Cost: recover_tx + new_tovault_tx fees.

Scenario 2 — Multi-party vault:
  If multiple parties share a vault and want to split funds to different
  destinations, each destination requires a SEPARATE vault with its own
  embedded sha_single_output.  No batched multi-destination withdrawal.

Scenario 3 — Destination compromise:
  If the destination wallet is compromised AFTER vault creation, the
  vault owner must recover to cold storage before the attacker can
  trigger + withdraw.  The CSV delay provides a defense window.

=== EMPIRICAL DEMONSTRATION ===
Phase 1: Verify destination lock — show that the withdraw leaf's embedded
  sha_single_output matches the expected destination.
Phase 2: Attempted destination override — try to withdraw to a different
  address.  Expected: REJECTED.
Phase 3: Recovery as escape hatch — demonstrate that recovery (cold key)
  bypasses the destination lock.  Measure recovery cost as the "rotation
  tax" for destination changes.
Phase 4: Cross-vault comparison of destination flexibility.
"""

import sys
from pathlib import Path

from adapters.base import VaultAdapter, VaultState, TxRecord
from harness.metrics import ExperimentResult, TxMetrics
from harness.regtest_caveats import emit_regtest_caveats, emit_fee_sensitivity_table
from experiments.registry import register


VAULT_AMOUNT = 49_999_900


@register(
    name="cat_csfs_destination_lock",
    description="CAT+CSFS destination lock: inflexible withdrawal target analysis",
    tags=["cat_csfs_only", "security", "configuration"],
    required_covenants=["cat_csfs"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    result = ExperimentResult(
        experiment="cat_csfs_destination_lock",
        covenant=adapter.name,
        params={"vault_amount_sats": VAULT_AMOUNT},
    )

    if adapter.name != "cat_csfs":
        result.observe("Skipping — CAT+CSFS-specific experiment.")
        return result

    try:
        _run_destination_lock(adapter, result)
    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")
        import traceback
        result.observe(traceback.format_exc())

    emit_regtest_caveats(
        result,
        experiment_specific=(
            "The destination lock is a consensus property of the script — "
            "sha_single_output is embedded at creation time and enforced by "
            "CSFS+CHECKSIG.  The withdrawal rejection and recovery escape "
            "hatch are both consensus behaviors directly applicable to mainnet."
        ),
    )
    emit_fee_sensitivity_table(
        result,
        threat_model_name="Destination rotation (recovery + re-vault)",
        vsize_rows=[
            {"label": "recovery_tx", "vsize": 130,
             "description": "Cold key recovery from vault-loop"},
            {"label": "new_tovault_tx", "vsize": 122,
             "description": "New vault deposit with updated destination"},
        ],
        vault_amount_sats=VAULT_AMOUNT,
    )

    return result


def _run_destination_lock(adapter, result):
    """Run the destination lock analysis."""
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
        NUMS_POINT_X, LEAF_VERSION_TAPSCRIPT, SIGHASH_SINGLE_ANYONECANPAY,
        compute_sha_single_output, build_control_block, tapleaf_hash,
        compute_tapscript_sighash, split_preimage_for_witness, schnorr_sign,
    )

    cat_rpc = adapter._cat_rpc
    rpc = adapter.rpc

    # ── Phase 1: Verify destination lock ──────────────────────────────
    result.observe("=" * 60)
    result.observe("PHASE 1: Verify destination lock at creation time")
    result.observe("=" * 60)

    vault = adapter.create_vault(VAULT_AMOUNT)
    plan = vault.extra["plan"]

    # Show the embedded destination constraint
    dest_spk = adapter.dest_wallet.p2wpkh_script_pubkey
    dest_amount = plan.amount_at_step(3)
    expected_sha_out = compute_sha_single_output(dest_amount, dest_spk)

    result.observe(f"Vault created: {vault.vault_txid[:16]}...")
    result.observe(f"Destination wallet: {adapter.dest_wallet.p2wpkh_address}")
    result.observe(f"Destination amount: {dest_amount} sats")
    result.observe(f"Embedded sha_single_output (withdraw): {expected_sha_out.hex()[:32]}...")
    result.observe(
        "The withdraw leaf script contains this hash as a constant.  "
        "Any withdrawal MUST produce an output that, when serialized "
        "and SHA256'd, matches this embedded value."
    )

    # Normal lifecycle to prove it works
    unvault = adapter.trigger_unvault(vault)
    result.observe(f"Triggered: {unvault.unvault_txid[:16]}...")

    withdraw_record = adapter.complete_withdrawal(unvault)
    result.observe(f"Withdrawal to embedded destination: {withdraw_record.txid[:16]}...")

    withdraw_info = rpc.get_tx_info(withdraw_record.txid)
    withdraw_vsize = withdraw_info["vsize"]
    result.observe(f"Withdraw vsize: {withdraw_vsize} vB")

    result.add_tx(TxMetrics(
        label="normal_withdraw",
        txid=withdraw_record.txid,
        vsize=withdraw_vsize,
        weight=withdraw_info.get("weight", 0),
        amount_sats=dest_amount,
        script_type="p2tr_cat_csfs",
    ))

    # ── Phase 2: Attempted destination override ───────────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 2: Attempted withdrawal to different address")
    result.observe("=" * 60)

    vault2 = adapter.create_vault(VAULT_AMOUNT)
    plan2 = vault2.extra["plan"]
    unvault2 = adapter.trigger_unvault(vault2)

    # Mine blocks for CSV
    cat_rpc.generatetoaddress(adapter.block_delay, adapter.fee_wallet.p2wpkh_address)

    # Build a withdraw tx targeting an ALTERNATIVE address
    alt_wallet = Wallet.generate(b"alternative-destination")
    alt_spk = alt_wallet.p2wpkh_script_pubkey

    trigger_txid_bytes = txid_to_bytes(unvault2.unvault_txid)
    mutated_tx = CMutableTransaction()
    mutated_tx.nVersion = 2
    mutated_tx.vin = [CTxIn(
        COutPoint(trigger_txid_bytes, 0),
        nSequence=adapter.block_delay,
    )]
    mutated_tx.vout = [CTxOut(
        plan2.amount_at_step(3),
        CScript(alt_spk),  # DIFFERENT destination
    )]

    # Sign with the hot key
    tl_hash = tapleaf_hash(plan2.loop_withdraw_script)

    sighash = compute_tapscript_sighash(
        tx=CTransaction.from_tx(mutated_tx),
        input_index=0,
        prevouts=[(trigger_txid_bytes, 0)],
        amounts=[plan2.amount_at_step(2)],
        scriptpubkeys=[plan2.loop_spk],
        tapleaf_hash_val=tl_hash,
        hash_type=SIGHASH_SINGLE_ANYONECANPAY,
    )

    sig = schnorr_sign(adapter.hot_wallet.secret, sighash)
    sig_with_hashtype = sig + bytes([SIGHASH_SINGLE_ANYONECANPAY])

    prefix, sha_out, suffix = split_preimage_for_witness(
        tx=CTransaction.from_tx(mutated_tx),
        input_index=0,
        prevout_txid_le=trigger_txid_bytes,
        prevout_vout=0,
        prevout_amount=plan2.amount_at_step(2),
        prevout_spk=plan2.loop_spk,
        tapleaf_hash_val=tl_hash,
    )

    result.observe(f"Alternative destination: {alt_wallet.p2wpkh_address}")
    result.observe(f"Mutated sha_single_output: {sha_out.hex()[:32]}...")
    result.observe(f"Embedded sha_single_output: {expected_sha_out.hex()[:32]}...")
    result.observe(f"Match: {sha_out == expected_sha_out}")

    control_block = build_control_block(
        NUMS_POINT_X,
        LEAF_VERSION_TAPSCRIPT,
        plan2.loop_output_parity,
        [plan2.loop_recover_hash],
    )

    witness_items = [
        sig_with_hashtype,
        sig,
        suffix,
        prefix,
        plan2.loop_withdraw_script,
        control_block,
    ]

    mutated_tx.wit = CTxWitness([
        CTxInWitness(CScriptWitness(witness_items))
    ])

    mutated_hex = CTransaction.from_tx(mutated_tx).serialize().hex()

    result.observe("Broadcasting withdrawal to alternative destination...")

    try:
        txid = cat_rpc.sendrawtransaction(mutated_hex)
        result.observe(
            f"UNEXPECTED: Alternative withdrawal ACCEPTED — {txid[:16]}...  "
            "The destination lock is not enforced!"
        )
        result.error = "Alternative destination withdrawal accepted"
    except Exception as e:
        err_str = str(e)
        result.observe(f"REJECTED: {err_str[:150]}")
        result.observe(
            "CONFIRMED: Withdrawal destination is locked at vault creation time.  "
            "The embedded sha_single_output in the withdraw leaf constrains the "
            "output to the original destination wallet."
        )

    # Clean up via recovery
    try:
        adapter.recover(unvault2)
    except Exception:
        pass

    # ── Phase 3: Recovery as escape hatch ─────────────────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 3: Recovery bypasses destination lock (escape hatch)")
    result.observe("=" * 60)

    vault3 = adapter.create_vault(VAULT_AMOUNT)
    plan3 = vault3.extra["plan"]

    result.observe(f"Vault created: {vault3.vault_txid[:16]}...")
    result.observe(
        "Recovery uses the recover leaf: simple cold_pk OP_CHECKSIG.  "
        "No introspection, no sha_single_output constraint.  The cold key "
        "can sweep funds to the cold wallet regardless of the embedded "
        "withdrawal destination."
    )

    # Recover directly from vault (no trigger needed)
    recover_record = adapter.recover(vault3)
    result.observe(f"Recovery from vault: {recover_record.txid[:16]}...")

    recover_info = rpc.get_tx_info(recover_record.txid)
    recover_vsize = recover_info["vsize"]
    result.observe(f"Recovery vsize: {recover_vsize} vB")

    result.add_tx(TxMetrics(
        label="recovery_escape",
        txid=recover_record.txid,
        vsize=recover_vsize,
        weight=recover_info.get("weight", 0),
        amount_sats=recover_record.amount_sats,
        script_type="p2tr_checksig",
    ))

    # Also measure recovery from vault-loop
    vault4 = adapter.create_vault(VAULT_AMOUNT)
    unvault4 = adapter.trigger_unvault(vault4)
    loop_recover = adapter.recover(unvault4)

    loop_recover_info = rpc.get_tx_info(loop_recover.txid)
    loop_recover_vsize = loop_recover_info["vsize"]
    result.observe(f"Recovery from vault-loop: {loop_recover.txid[:16]}... ({loop_recover_vsize} vB)")

    result.add_tx(TxMetrics(
        label="recovery_from_loop",
        txid=loop_recover.txid,
        vsize=loop_recover_vsize,
        weight=loop_recover_info.get("weight", 0),
        amount_sats=loop_recover.amount_sats,
        script_type="p2tr_checksig",
    ))

    # Rotation cost analysis
    rotation_cost_vsize = recover_vsize + 122  # recovery + new tovault
    result.observe(
        f"DESTINATION ROTATION COST: recovery ({recover_vsize} vB) + "
        f"new vault deposit (~122 vB) = ~{rotation_cost_vsize} vB total"
    )
    for fee_rate in [1, 10, 50, 100]:
        cost_sats = rotation_cost_vsize * fee_rate
        pct = cost_sats / VAULT_AMOUNT * 100
        result.observe(
            f"  At {fee_rate:>3} sat/vB: rotation cost = {cost_sats:>7,} sats "
            f"({pct:.4f}% of vault)"
        )

    # ── Phase 4: Cross-vault comparison ───────────────────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 4: Destination flexibility comparison")
    result.observe("=" * 60)
    result.observe(
        "  CTV:      TWO pre-committed destinations (hot + cold).  Chosen "
        "at trigger time by broadcasting tohot_tx or tocold_tx.  "
        "Limited flexibility: only two options, fixed at creation."
    )
    result.observe(
        "  CCV:      Destination committed at TRIGGER TIME via CTV hash "
        "in the augmented state.  Trigger key holder chooses.  "
        "Full flexibility at the cost of trusting the trigger key."
    )
    result.observe(
        "  OP_VAULT: Destination committed at TRIGGER TIME via CTV template "
        "passed to OP_VAULT.  Trigger key holder chooses.  "
        "Full flexibility at the cost of trusting the trigger key."
    )
    result.observe(
        "  CAT+CSFS: SINGLE pre-committed destination.  Locked at vault "
        "creation.  No flexibility.  Destination changes require "
        "recovery + re-vaulting."
    )
    result.observe(
        "  FLEXIBILITY RANKING:"
    )
    result.observe(
        "    1. CCV/OP_VAULT (trigger-time destination, full flexibility)"
    )
    result.observe(
        "    2. CTV (two pre-committed destinations, limited choice)"
    )
    result.observe(
        "    3. CAT+CSFS (single locked destination, no choice)"
    )
    result.observe(
        "  SECURITY TRADEOFF: Destination lock = fewer attack paths.  "
        "The hot key CANNOT redirect funds to an attacker address because "
        "the destination is embedded in the script.  This is the same "
        "property that makes destination rotation expensive."
    )
    result.observe(
        "  DESIGN INSIGHT: The destination lock is a consequence of embedding "
        "sha_single_output as a script constant.  To achieve trigger-time "
        "destination flexibility, the script would need to accept the "
        "destination from the witness — but then the hot key could choose "
        "any destination, defeating the covenant's purpose."
    )
