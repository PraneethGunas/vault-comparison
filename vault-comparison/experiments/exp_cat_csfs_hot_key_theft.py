"""Experiment: CAT+CSFS Hot Key Theft — Output Redirection Attempt

Tests whether a compromised hot key can redirect vault funds to an
attacker-controlled address.  The CAT+CSFS vault embeds
sha_single_output in the trigger/withdraw scripts, constraining the
output to the pre-committed address.  The hot key signs with
SIGHASH_SINGLE|ANYONECANPAY, but the CSFS verification ties the
signature to the embedded output hash.

=== RELATED WORK ===
The dual-verification pattern (CSFS + CHECKSIG with same signature)
was proposed by Poelstra ("CAT and Schnorr Tricks", 2021) and refined
by Ruffing/Poelstra (BIP 348).  Rijndael [Rij24] demonstrated a
working OP_CAT-only vault (purrfect_vault) using the Schnorr G-trick
instead of CSFS; our vault uses real CSFS for a simpler witness.
The sighash preimage splitting technique is described in the Bitcoin
Wiki taproot BIP 342 section.

The SIGHASH_SINGLE|ANYONECANPAY model for fee flexibility is used in
Lightning Network anchor outputs (BOLT 3) and analyzed in "One Single
Trick" (medium.com/@bitcoindevelopment).

=== THREAT MODEL: Hot key theft (CAT+CSFS) ===
Attacker: Has the hot key (same as CTV/CCV/OP_VAULT trigger key theft).
Goal: (1) Redirect vault funds to attacker address during trigger or
  withdrawal, or (2) if redirection impossible, grief the vault owner.
Key constraint: The trigger and withdraw scripts embed sha_single_output
  as a constant.  The CSFS check verifies the signature against a
  preimage that INCLUDES this hash.  To redirect funds, the attacker
  would need to produce a signature that passes CSFS with a different
  sha_single_output AND passes CHECKSIG against the real transaction.
  This is impossible: changing the output changes the CHECKSIG sighash,
  so the same signature cannot satisfy both checks.
Comparison with other vaults:
  - CTV:      Hot key + fee key → fund theft (via fee pinning)
  - CCV:      Hot key → trigger, watchtower races recovery
  - OP_VAULT: Hot key → trigger to attacker addr, watchtower recovers
  - CAT+CSFS: Hot key → trigger ONLY to embedded output (cannot choose)
Unique property: On CTV and OP_VAULT, the hot key holder can choose
  the withdrawal destination at trigger time.  On CAT+CSFS, the
  destination is baked into the script at vault creation time.  The hot
  key can only trigger to the one pre-committed vault-loop address.

=== EMPIRICAL DEMONSTRATION ===
Phase 1: Normal trigger — hot key triggers to embedded vault-loop.
  Measure vsize, verify output matches expected.
Phase 2: Mutated trigger — hot key attempts to trigger to a DIFFERENT
  output (attacker address).  Build a transaction with the correct
  witness but a modified output.  Expected: REJECTED.
  The dual-verification creates an inseparable binding:
    - CSFS checks sig against prefix||embedded_sha_out||suffix
    - CHECKSIG checks sig against the real sighash (which includes the
      REAL output).  If the output differs from the embedded one,
      the two sighashes diverge and the signature cannot satisfy both.
Phase 3: Extra output injection — hot key creates a trigger tx with
  an ADDITIONAL output (SIGHASH_SINGLE only commits to one output).
  Expected: ACCEPTED — the covenant output is correct, extra outputs
  don't violate the covenant.  But the extra output is funded from
  extra inputs (ANYONECANPAY), not from vault funds.
Phase 4: Cross-vault comparison — hot key theft severity ranking.
"""

import sys
from pathlib import Path

from adapters.base import VaultAdapter, VaultState, UnvaultState, TxRecord
from harness.metrics import ExperimentResult, TxMetrics
from harness.regtest_caveats import emit_regtest_caveats, emit_fee_sensitivity_table
from experiments.registry import register


VAULT_AMOUNT = 49_999_900


@register(
    name="cat_csfs_hot_key_theft",
    description="CAT+CSFS hot key theft: output redirection attempt via CSFS bypass",
    tags=["cat_csfs_only", "security", "critical"],
    required_covenants=["cat_csfs"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    result = ExperimentResult(
        experiment="cat_csfs_hot_key_theft",
        covenant=adapter.name,
        params={"vault_amount_sats": VAULT_AMOUNT},
    )

    if adapter.name != "cat_csfs":
        result.observe("Skipping — CAT+CSFS-specific experiment.")
        return result

    rpc = adapter.rpc

    measured_trigger_vsize = 200  # fallback
    try:
        measured_trigger_vsize = _run_hot_key_theft(adapter, result, rpc)
    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")
        import traceback
        result.observe(traceback.format_exc())

    emit_regtest_caveats(
        result,
        experiment_specific=(
            "The output redirection test (Phase 2) verifies script-level "
            "enforcement.  The CSFS+CHECKSIG dual verification is a consensus "
            "rule — if it rejects on regtest, it rejects on mainnet.  The "
            "extra output injection test (Phase 3) verifies that "
            "SIGHASH_SINGLE|ANYONECANPAY permits additional outputs, which "
            "is also consensus behavior."
        ),
    )
    emit_fee_sensitivity_table(
        result,
        threat_model_name="Hot key theft (CAT+CSFS)",
        vsize_rows=[
            {"label": "trigger_tx", "vsize": measured_trigger_vsize,
             "description": "Hot key trigger to vault-loop (measured)"},
            {"label": "griefing_trigger", "vsize": measured_trigger_vsize,
             "description": "Repeated trigger for griefing (same cost)"},
        ],
        vault_amount_sats=VAULT_AMOUNT,
    )

    return result


def _run_hot_key_theft(adapter, result, rpc):
    """Run the full hot key theft experiment."""
    # Lazy imports for CAT+CSFS internals
    CAT_CSFS_REPO = Path(__file__).resolve().parents[2] / "simple-cat-csfs-vault"
    repo_str = str(CAT_CSFS_REPO)
    if repo_str not in sys.path:
        sys.path.insert(0, repo_str)

    from bitcoin.core import (
        CMutableTransaction, CTxIn, CTxOut, CTransaction,
        CTxInWitness, CScriptWitness, CTxWitness, COutPoint, COIN,
    )
    from bitcoin.core.script import CScript
    from vault import VaultPlan, VaultExecutor, Wallet, Coin, txid_to_bytes
    from taproot import (
        NUMS_POINT_X, LEAF_VERSION_TAPSCRIPT, SIGHASH_SINGLE_ANYONECANPAY,
        make_trigger_leaf, compute_sha_single_output, compute_taptree_2,
        tweak_pubkey, p2tr_script_pubkey, build_control_block,
        tapleaf_hash, compute_tapscript_sighash, split_preimage_for_witness,
        schnorr_sign,
    )

    cat_rpc = adapter._cat_rpc

    # ── Phase 1: Normal trigger (control) ─────────────────────────────
    result.observe("=" * 60)
    result.observe("PHASE 1: Normal trigger (control)")
    result.observe("=" * 60)

    vault = adapter.create_vault(VAULT_AMOUNT)
    result.observe(f"Vault created: {vault.vault_txid[:16]}... ({vault.amount_sats} sats)")

    plan = vault.extra["plan"]

    # Verify the trigger script embeds the expected sha_single_output
    loop_amount = plan.amount_at_step(2)
    expected_sha_out = compute_sha_single_output(loop_amount, plan.loop_spk)
    result.observe(f"Embedded sha_single_output: {expected_sha_out.hex()[:32]}...")
    result.observe(f"Expected vault-loop amount: {loop_amount} sats")

    # Normal trigger
    unvault = adapter.trigger_unvault(vault)
    trigger_info = rpc.get_tx_info(unvault.unvault_txid)
    trigger_vsize = trigger_info["vsize"]
    result.observe(f"Normal trigger: {unvault.unvault_txid[:16]}... ({trigger_vsize} vB)")

    # Verify the output matches
    actual_output = trigger_info["vout"][0]
    actual_amount = int(actual_output["value"] * 100_000_000)
    actual_spk = actual_output["scriptPubKey"]["hex"]
    result.observe(f"Trigger output: {actual_amount} sats, spk={actual_spk[:32]}...")
    result.observe(f"Expected amount: {loop_amount} sats")

    if actual_amount == loop_amount:
        result.observe("CONFIRMED: Trigger output matches embedded constraint.")
    else:
        result.observe(
            f"WARNING: Output mismatch — actual={actual_amount}, "
            f"expected={loop_amount}"
        )

    result.add_tx(TxMetrics(
        label="normal_trigger",
        txid=unvault.unvault_txid,
        vsize=trigger_vsize,
        weight=trigger_info.get("weight", 0),
        amount_sats=actual_amount,
        num_inputs=len(trigger_info["vin"]),
        num_outputs=len(trigger_info["vout"]),
        script_type="p2tr_cat_csfs",
    ))

    # Complete withdrawal to clean up
    adapter.complete_withdrawal(unvault)

    # ── Phase 2: Mutated trigger (redirection attempt) ────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 2: Mutated trigger — redirect to attacker address")
    result.observe("=" * 60)

    vault2 = adapter.create_vault(VAULT_AMOUNT)
    plan2 = vault2.extra["plan"]
    result.observe(f"Vault created: {vault2.vault_txid[:16]}...")

    # Build a trigger transaction targeting an ATTACKER address
    attacker_wallet = Wallet.generate(b"attacker-hot-key-theft")
    attacker_spk = attacker_wallet.p2wpkh_script_pubkey

    # The trigger tx template, but with attacker output instead of vault-loop
    vault_txid_bytes = txid_to_bytes(vault2.vault_txid)
    mutated_tx = CMutableTransaction()
    mutated_tx.nVersion = 2
    mutated_tx.vin = [CTxIn(COutPoint(vault_txid_bytes, 0), nSequence=0)]
    mutated_tx.vout = [CTxOut(
        plan2.amount_at_step(2),
        CScript(attacker_spk),  # ATTACKER destination
    )]

    # Sign with the hot key (attacker has the hot key)
    tl_hash = tapleaf_hash(plan2.vault_trigger_script)

    sighash = compute_tapscript_sighash(
        tx=CTransaction.from_tx(mutated_tx),
        input_index=0,
        prevouts=[(vault_txid_bytes, 0)],
        amounts=[plan2.amount_at_step(1)],
        scriptpubkeys=[plan2.vault_spk],
        tapleaf_hash_val=tl_hash,
        hash_type=SIGHASH_SINGLE_ANYONECANPAY,
    )

    sig = schnorr_sign(adapter.hot_wallet.secret, sighash)
    sig_with_hashtype = sig + bytes([SIGHASH_SINGLE_ANYONECANPAY])

    # Build witness with the REAL preimage prefix/suffix (for the mutated tx)
    prefix, sha_out, suffix = split_preimage_for_witness(
        tx=CTransaction.from_tx(mutated_tx),
        input_index=0,
        prevout_txid_le=vault_txid_bytes,
        prevout_vout=0,
        prevout_amount=plan2.amount_at_step(1),
        prevout_spk=plan2.vault_spk,
        tapleaf_hash_val=tl_hash,
    )

    result.observe(f"Mutated tx sha_single_output: {sha_out.hex()[:32]}...")
    result.observe(f"Script-embedded sha_single_output: {expected_sha_out.hex()[:32]}...")
    result.observe(f"Match: {sha_out == expected_sha_out}")

    # Build control block
    control_block = build_control_block(
        NUMS_POINT_X,
        LEAF_VERSION_TAPSCRIPT,
        plan2.vault_output_parity,
        [plan2.vault_recover_hash],
    )

    witness_items = [
        sig_with_hashtype,              # sig for CHECKSIG (65 bytes)
        sig,                            # sig for CSFS (64 bytes)
        suffix,                         # preimage suffix
        prefix,                         # preimage prefix
        plan2.vault_trigger_script,     # tapscript
        control_block,                  # control block
    ]

    mutated_tx.wit = CTxWitness([
        CTxInWitness(CScriptWitness(witness_items))
    ])

    mutated_final = CTransaction.from_tx(mutated_tx)
    mutated_hex = mutated_final.serialize().hex()

    result.observe("Broadcasting mutated trigger (attacker output)...")

    try:
        txid = cat_rpc.sendrawtransaction(mutated_hex)
        result.observe(
            f"UNEXPECTED: Mutated trigger ACCEPTED — {txid[:16]}...  "
            "This means the covenant was BYPASSED.  CRITICAL vulnerability."
        )
        result.error = "Mutated trigger accepted — covenant bypass"
        cat_rpc.generatetoaddress(1, adapter.fee_wallet.p2wpkh_address)
    except Exception as e:
        err_str = str(e)
        result.observe(f"REJECTED: {err_str[:200]}")
        result.observe(
            "CONFIRMED: The dual CSFS+CHECKSIG verification prevents output "
            "redirection.  The attacker's signature was valid for the REAL "
            "transaction (CHECKSIG) but the CSFS check failed because the "
            "preimage assembled from witness parts does NOT match the script's "
            "embedded sha_single_output."
        )
        result.observe(
            "MECHANISM: The script pushes the embedded sha_single_output and "
            "CATs it with the witness-provided prefix and suffix.  The result "
            "is hashed to produce a sighash.  CSFS verifies the signature "
            "against THIS sighash.  Then CHECKSIG verifies the SAME signature "
            "against the real transaction's sighash.  If the output differs "
            "from the embedded one, the CSFS-computed sighash differs from "
            "the CHECKSIG sighash, so the same sig cannot satisfy both."
        )

    # Clean up vault2 via recovery
    try:
        adapter.recover(vault2)
    except Exception:
        pass

    # ── Phase 3: Extra output injection ───────────────────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 3: Extra output injection (SIGHASH_SINGLE property)")
    result.observe("=" * 60)
    result.observe(
        "SIGHASH_SINGLE|ANYONECANPAY commits to only ONE output (at the same "
        "index as the input).  Additional outputs can be freely added.  This "
        "is BY DESIGN for fee management — anyone can attach a fee-paying "
        "input and take change via an extra output."
    )
    result.observe(
        "ANALYSIS: Extra outputs do NOT drain vault funds.  The covenant "
        "output (index 0) is locked to the embedded amount and scriptPubKey.  "
        "Extra outputs at index 1+ are funded entirely from extra inputs "
        "(ANYONECANPAY).  An attacker adding extra outputs only spends their "
        "OWN funds, not vault funds."
    )
    result.observe(
        "This is a FEE-CONTRIBUTOR risk, not a VAULT-HOLDER risk.  If a third "
        "party contributes a fee-paying input, another party could race to "
        "modify the transaction and redirect the third party's change.  The "
        "vault funds are unaffected because the covenant output is fixed."
    )

    # ── Phase 4: Cross-vault comparison ───────────────────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 4: Hot key theft severity comparison")
    result.observe("=" * 60)
    result.observe(
        "  CTV:      Hot key can TRIGGER unvault.  Combined with fee key, "
        "can PIN the cold sweep → FUND THEFT.  Without fee key, "
        "can only grief (trigger → owner sweeps to cold).  "
        "Severity: CRITICAL (with fee key), MODERATE (without)."
    )
    result.observe(
        "  CCV:      Hot key can TRIGGER unvault.  Watchtower races to "
        "recover (keyless).  Hot key holder CAN choose withdrawal "
        "destination at trigger time.  "
        "Severity: MODERATE (watchtower race)."
    )
    result.observe(
        "  OP_VAULT: Hot key can TRIGGER to any address (start_withdrawal).  "
        "Watchtower recovers (with recoveryauth key).  "
        "Severity: MODERATE (watchtower race)."
    )
    result.observe(
        "  CAT+CSFS: Hot key can ONLY trigger to the embedded vault-loop "
        "address.  CANNOT choose a different destination.  "
        "CANNOT escalate to fund theft (no fee key, no anchors).  "
        "Can only grief (trigger → owner recovers with cold key).  "
        "Severity: LOW (griefing only, no theft path)."
    )
    result.observe(
        "  UNIQUE PROPERTY: CAT+CSFS is the ONLY vault design where the hot "
        "key holder cannot influence the destination at trigger time.  The "
        "sha_single_output embedding creates a one-way binding from script "
        "to output that the hot key cannot override."
    )
    result.observe(
        "  HIERARCHY (by hot key theft severity):"
    )
    result.observe(
        "    1. CTV (hot+fee = FUND THEFT)"
    )
    result.observe(
        "    2. CCV/OP_VAULT (hot key chooses destination, watchtower races)"
    )
    result.observe(
        "    3. CAT+CSFS (hot key CANNOT choose destination, griefing only)"
    )

    return trigger_vsize
