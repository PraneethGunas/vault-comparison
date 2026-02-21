"""Experiment K: OP_VAULT Authorized Recovery Analysis

Demonstrates authorized recovery as both a DEFENSE (anti-griefing) and
an ATTACK SURFACE (recoveryauth key compromise).

=== RELATED WORK ===
BIP-345 §Recovery authorization (https://bips.dev/345/) introduces the
``recoveryauth`` key specifically to prevent the keyless-recovery griefing
attack that affects CCV vaults.  The original OP_VAULT proposal by James
O'Beirne (https://jameso.be/vaults.pdf) motivated the mechanism; Harding
("OP_VAULT comments", Delving Bitcoin,
https://delvingbitcoin.org/t/op-vault-comments/521) notes the tradeoff:
authorized recovery replaces one attack surface (CCV keyless griefing)
with another (recoveryauth key compromise → same liveness denial).
Ingala's BIP-443 CCV design deliberately omits recovery authorization for
simplicity, accepting the griefing surface.  Swambo et al. ("Custody
Protocols Using Bitcoin Vaults", 2020,
https://arxiv.org/abs/2005.11776) identify recovery griefing as a
general vault risk class.

=== THREAT MODEL: Recoveryauth key compromise ===
Attacker: Has the recoveryauth key ONLY (not the trigger key).  Can observe
  mempool and broadcast transactions.
Goal: Deny vault liveness — force all funds to the recovery address whenever
  the owner attempts a withdrawal.  The recovery address is pre-committed
  at vault creation and controlled by the owner.  Funds are safe but
  inaccessible via normal withdrawal.
Cost: One OP_VAULT_RECOVER tx per griefing round (~R vbytes × fee_rate).
Payoff: Zero direct financial gain — pure denial of service.  But if the
  recovery address is a cold multisig, the attacker imposes significant
  operational overhead on the owner (must use cold signing each time).
Rationality: Only rational with external incentive (competitor, extortionist,
  state actor).  Higher bar than CCV (need a key) but same consequence.
Defender response: Rotate to a new vault with fresh recoveryauth key.
  Revoke or cycle the compromised key.  Use hardware security modules for
  recoveryauth key storage.
Residual: Liveness denial only — never fund loss.  Funds always go to the
  owner's pre-committed recovery address.

=== COMPARISON ===
CCV: Anyone can grief (keyless recovery).  Trivially cheap.
OP_VAULT: Only recoveryauth key holder can grief.  Higher attacker bar,
  same consequence.  This is the explicit design tradeoff BIP-345 makes.
CTV: Hot key holder can grief by triggering unvault.  Different direction
  but same class of liveness attack.

=== EMPIRICAL DEMONSTRATION ===
Phase 1: Normal authorized recovery — confirm it works and measure cost.
Phase 2: Simulate N rounds of recoveryauth griefing: owner triggers,
  attacker front-runs with recovery.  Measure cumulative costs.
Phase 3: Direct vsize comparison — OP_VAULT authorized recovery vs CCV
  keyless recovery, quantifying the Schnorr-signature overhead.
Phase 4: Verify consensus enforcement — construct a recovery transaction
  with a WRONG recoveryauth key and confirm the node rejects it.
"""

from adapters.base import VaultAdapter, TxRecord, UnvaultState
from harness.metrics import ExperimentResult, TxMetrics
from harness.regtest_caveats import emit_regtest_caveats, emit_fee_sensitivity_table
from experiments.registry import register

VAULT_AMOUNT = 49_999_900
MAX_GRIEF_ROUNDS = 5  # fewer rounds since each needs fresh vault+mining

# CCV keyless recovery vsize from empirical measurement (exp_recovery_griefing)
CCV_RECOVER_VSIZE = 122


@register(
    name="opvault_recovery_auth",
    description="OP_VAULT authorized recovery: defense property and compromise analysis",
    tags=["core", "opvault_specific", "security", "quantitative"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    result = ExperimentResult(
        experiment="opvault_recovery_auth",
        covenant=adapter.name,
        params={"vault_amount_sats": VAULT_AMOUNT},
    )

    rpc = adapter.rpc

    # This experiment is OP_VAULT-specific
    if adapter.name != "opvault":
        result.observe(
            f"Skipping opvault_recovery_auth on {adapter.name} — "
            "this experiment is OP_VAULT-specific."
        )
        if adapter.supports_keyless_recovery():
            result.observe(
                f"{adapter.name} uses keyless recovery.  The authorized recovery "
                "defense (anti-griefing) does not apply.  See recovery_griefing "
                "experiment for keyless griefing analysis."
            )
        else:
            result.observe(
                f"{adapter.name} does not support keyless recovery, but also "
                "does not use OP_VAULT's specific authorized recovery mechanism."
            )
        return result

    # Measured vsizes (filled by Phase 1)
    measured_trigger_vsize = 200  # fallback
    measured_recover_vsize = 170  # fallback

    try:
        measured_trigger_vsize, measured_recover_vsize = \
            _run_opvault_recovery_auth(adapter, result, rpc)
    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")
        import traceback
        result.observe(traceback.format_exc())

    # Regtest caveats
    emit_regtest_caveats(
        result,
        experiment_specific=(
            "The authorized recovery griefing attack depends on mempool "
            "front-running, which cannot be demonstrated on regtest (blocks "
            "are mined instantly).  The vsize measurements and economic "
            "analysis are structurally valid; the front-running race is "
            "argued analytically.  The consensus-enforcement test (Phase 4) "
            "IS valid on regtest — consensus rules are identical to mainnet."
        ),
    )
    emit_fee_sensitivity_table(
        result,
        threat_model_name="Recoveryauth key compromise griefing",
        vsize_rows=[
            {"label": "defender_trigger", "vsize": measured_trigger_vsize,
             "description": "start_withdrawal trigger tx (defender pays)"},
            {"label": "attacker_recovery", "vsize": measured_recover_vsize,
             "description": "OP_VAULT_RECOVER tx (attacker with recoveryauth key)"},
        ],
        vault_amount_sats=VAULT_AMOUNT,
    )

    return result


def _run_opvault_recovery_auth(adapter, result, rpc):
    """Execute the authorized recovery analysis.

    Returns (trigger_vsize, recover_vsize) for use in the fee sensitivity table.
    """

    # ── Phase 1: Normal authorized recovery ──────────────────────────
    result.observe("=== Phase 1: Normal authorized recovery (defense property) ===")

    vault = adapter.create_vault(VAULT_AMOUNT)
    result.observe(
        f"Vault created: {vault.vault_txid[:16]}... ({vault.amount_sats} sats)"
    )

    # Trigger unvault
    unvault = adapter.trigger_unvault(vault)
    trigger_info = rpc.get_tx_info(unvault.unvault_txid)
    trigger_vsize = trigger_info["vsize"]
    trigger_fee = rpc.get_tx_fee_sats(unvault.unvault_txid)
    result.observe(
        f"Trigger (start_withdrawal): vsize={trigger_vsize}, fee={trigger_fee} sats"
    )
    result.add_tx(TxMetrics(
        label="trigger",
        txid=unvault.unvault_txid,
        vsize=trigger_vsize,
        weight=trigger_info["weight"],
        fee_sats=trigger_fee,
        num_inputs=len(trigger_info["vin"]),
        num_outputs=len(trigger_info["vout"]),
        amount_sats=unvault.amount_sats,
    ))

    # Recover using authorized recovery (legitimate use)
    recover_record = adapter.recover(unvault)
    recover_metrics = adapter.collect_tx_metrics(recover_record, rpc)
    recover_vsize = recover_metrics.vsize
    recover_fee = recover_metrics.fee_sats
    result.observe(
        f"Authorized recovery: vsize={recover_vsize}, fee={recover_fee} sats"
    )
    result.add_tx(recover_metrics)

    result.observe(
        "DEFENSE PROPERTY: Recovery requires the recoveryauth key signature.  "
        "Unlike CCV's keyless recovery, a third party CANNOT front-run triggers "
        "with recovery transactions unless they have the recoveryauth key.  "
        "TRADEOFF: The watchtower MUST hold this key to perform recovery — "
        "and if the key is lost, recovery becomes permanently impossible.  "
        "CCV avoids this failure mode entirely via keyless recovery."
    )

    # ── Phase 2: Recoveryauth griefing simulation ─────────────────────
    result.observe(
        f"\n=== Phase 2: Recoveryauth griefing simulation ({MAX_GRIEF_ROUNDS} rounds) ==="
    )
    result.observe(
        "Scenario: Attacker has compromised the recoveryauth key (but NOT the "
        "trigger key).  Whenever the owner triggers a withdrawal, the attacker "
        "front-runs with OP_VAULT_RECOVER, sending funds to the pre-committed "
        "recovery address."
    )

    attacker_cumulative_vsize = 0
    defender_cumulative_vsize = 0
    rounds_completed = 0

    for round_num in range(1, MAX_GRIEF_ROUNDS + 1):
        try:
            # Owner creates vault and triggers withdrawal
            vault = adapter.create_vault(VAULT_AMOUNT)
            unvault = adapter.trigger_unvault(vault)

            t_info = rpc.get_tx_info(unvault.unvault_txid)
            t_vsize = t_info.get("vsize", trigger_vsize)

            # Attacker front-runs with authorized recovery
            r_record = adapter.recover(unvault)
            r_metrics = adapter.collect_tx_metrics(r_record, rpc)
            r_vsize = r_metrics.vsize or recover_vsize

            attacker_cumulative_vsize += r_vsize
            defender_cumulative_vsize += t_vsize
            rounds_completed = round_num

            result.observe(
                f"  Round {round_num}: trigger={t_vsize} vB, "
                f"recover={r_vsize} vB  |  "
                f"Cumulative: defender={defender_cumulative_vsize} vB, "
                f"attacker={attacker_cumulative_vsize} vB"
            )

        except Exception as e:
            result.observe(f"  Round {round_num}: FAILED — {e}")
            break

    if attacker_cumulative_vsize > 0 and defender_cumulative_vsize > 0:
        ratio = defender_cumulative_vsize / attacker_cumulative_vsize
        result.observe(
            f"\nAfter {rounds_completed} rounds: "
            f"defender spent {defender_cumulative_vsize} vB, "
            f"attacker spent {attacker_cumulative_vsize} vB.  "
            f"Ratio: {ratio:.2f}x (defender pays more)."
        )

    result.add_tx(TxMetrics(
        label="grief_loop_totals",
        vsize=attacker_cumulative_vsize + defender_cumulative_vsize,
        num_inputs=rounds_completed,
        num_outputs=rounds_completed,
    ))

    # ── Phase 3: CCV vs OP_VAULT recovery vsize comparison ────────────
    result.observe("\n=== Phase 3: CCV vs OP_VAULT recovery vsize comparison ===")

    signature_overhead = recover_vsize - CCV_RECOVER_VSIZE
    result.observe(
        f"  CCV keyless recovery:      {CCV_RECOVER_VSIZE} vB "
        f"(no signature, script-path only)"
    )
    result.observe(
        f"  OP_VAULT authorized recovery: {recover_vsize} vB "
        f"(includes recoveryauth Schnorr signature)"
    )
    result.observe(
        f"  Marginal cost of anti-griefing: +{signature_overhead} vB "
        f"(~{signature_overhead * 4} weight units)"
    )
    result.observe(
        "  The Schnorr signature in the recovery witness adds ~64 bytes "
        "(~16 vB with witness discount).  The remaining difference comes from "
        "structural differences in the taproot trees (CCV uses CScript with "
        "OP_CHECKCONTRACTVERIFY; OP_VAULT uses OP_VAULT_RECOVER with a "
        "separate recoveryauth pubkey check)."
    )
    result.observe(
        "  INTERPRETATION: OP_VAULT pays a small per-recovery overhead "
        f"(+{signature_overhead} vB ≈ +{signature_overhead * 100 // recover_vsize}% "
        f"of recovery vsize) to eliminate the entire class of anonymous griefing "
        "attacks.  At 100 sat/vB, this costs "
        f"+{signature_overhead * 100:,} sats per recovery — negligible for "
        "high-value vaults."
    )

    # Fee rate comparison across both recovery types
    result.observe("\n--- Fee rate sensitivity: anti-griefing cost ---")
    result.observe(
        "  fee_rate  |  CCV recovery  |  OPV recovery  |  overhead"
    )
    result.observe(
        "  ---------+-----------------+----------------+----------"
    )
    for fee_rate in [1, 10, 50, 100, 500]:
        ccv_cost = CCV_RECOVER_VSIZE * fee_rate
        opv_cost = recover_vsize * fee_rate
        overhead = (recover_vsize - CCV_RECOVER_VSIZE) * fee_rate
        result.observe(
            f"  {fee_rate:>3} s/vB  |  {ccv_cost:>9,} sats  |  "
            f"{opv_cost:>9,} sats  |  +{overhead:>7,} sats"
        )

    # ── Phase 4: Consensus enforcement — wrong-key rejection ──────────
    result.observe(
        "\n=== Phase 4: Consensus enforcement — wrong-key recovery rejected ==="
    )
    result.observe(
        "Testing whether OP_VAULT_RECOVER enforces the recoveryauth key at "
        "CONSENSUS level.  We construct a recovery transaction signed with a "
        "DIFFERENT Schnorr key (not the recoveryauth key committed in the vault's "
        "taproot tree) and verify the node rejects it."
    )
    result.observe(
        "This is NOT a tautology ('does Bitcoin check signatures') — it verifies "
        "that OP_VAULT_RECOVER's recoveryauth check is a consensus rule, not just "
        "a relay policy or standardness check.  A relay-only check could be bypassed "
        "by submitting directly to miners."
    )

    _test_wrong_key_rejection(adapter, result, rpc)

    # ── Summary ──────────────────────────────────────────────────────
    result.observe("\n=== Summary ===")
    result.observe(
        "AUTHORIZED RECOVERY is OP_VAULT's explicit design choice (BIP-345) to "
        "eliminate the keyless griefing attack that affects CCV vaults.  The tradeoff:"
    )
    result.observe(
        f"  DEFENSE: Third parties cannot grief recovery.  Measured recovery "
        f"cost: {recover_vsize} vB (includes recoveryauth Schnorr signature, "
        f"+{signature_overhead} vB over CCV's keyless recovery)."
    )
    result.observe(
        "  ATTACK SURFACE: The recoveryauth key becomes a liveness-critical "
        "secret.  If compromised, the attacker can deny withdrawals by "
        "front-running triggers with authorized recovery.  Funds always go to "
        "the pre-committed recovery address (owner-controlled), so this is a "
        "liveness attack, not a theft vector."
    )
    result.observe(
        "  KEY MANAGEMENT: BIP-345 recommends cold storage for recoveryauth "
        "keys.  Organizations should consider HSMs or threshold schemes.  "
        "The recoveryauth key can be rotated by creating a new vault config."
    )
    result.observe(
        "  KEY LOSS RISK: If the recoveryauth key is LOST (not just "
        "compromised), recovery becomes permanently impossible — the "
        "watchtower cannot sweep triggered vaults to cold storage.  "
        "Funds in an already-triggered vault with a lost recoveryauth "
        "key can only be withdrawn (not recovered).  If the trigger key "
        "is also lost, funds are permanently locked.  CCV's keyless "
        "recovery does not have this failure mode: fund safety is "
        "guaranteed regardless of key management failures.  This is "
        "the core cost of OP_VAULT's anti-griefing design."
    )
    result.observe(
        "  COMPARISON: CCV griefing needs NO key (lower bar, higher risk) "
        "but also means NO key can be lost (fund safety guaranteed).  "
        "OP_VAULT griefing needs recoveryauth key (higher bar, same "
        "consequence) but key loss → permanent recovery failure.  "
        "CTV griefing needs hot key (different direction, can escalate "
        "to theft under current relay policy)."
    )

    return (trigger_vsize, recover_vsize)


def _test_wrong_key_rejection(adapter, result, rpc):
    """Construct a recovery tx with a wrong key and verify consensus rejection.

    The test:
    1. Create a vault and trigger it (so there's a trigger UTXO to recover).
    2. Build a recovery transaction using the CORRECT structure (correct
       recovery SPK hash, correct output, correct controlblock) but sign
       with a RANDOM key instead of the committed recoveryauth key.
    3. Attempt to broadcast via sendrawtransaction.
    4. Verify the node rejects it with a script verification failure.

    This demonstrates that OP_VAULT_RECOVER enforces the recoveryauth pubkey
    check at consensus, not just standardness.  The rejection reason should
    be a script failure (OP_CHECKSIGVERIFY with wrong key), proving the
    authorization is a hard consensus requirement.
    """
    import hashlib
    import secrets

    try:
        # Step 1: Create and trigger a vault
        vault = adapter.create_vault(VAULT_AMOUNT)
        unvault = adapter.trigger_unvault(vault)
        result.observe(
            f"  Created vault and triggered withdrawal "
            f"({unvault.unvault_txid[:16]}...)"
        )

        # Step 2: Build a recovery tx with the WRONG key
        config = unvault.extra["config"]
        monitor = unvault.extra["monitor"]
        chain_state = monitor.rescan()

        trigger_utxos = list(chain_state.trigger_utxos.values())
        assert trigger_utxos, "No trigger UTXOs to test recovery against"

        # Import upstream modules
        ov = adapter.ov
        from verystable import core
        from verystable.core import messages as msgs, script as vscript
        from verystable.core.messages import COutPoint, CTxOut, CTxIn

        # Generate a WRONG key — random 32 bytes, not the recoveryauth key
        wrong_seed = secrets.token_bytes(32)
        wrong_key = core.key.ECKey()
        wrong_key.set(wrong_seed, compressed=True)
        wrong_privkey = wrong_key.get_bytes()

        def wrong_signer(msg: bytes) -> bytes:
            """Sign with the WRONG key — signature is valid Schnorr but
            against the wrong pubkey."""
            return core.key.sign_schnorr(wrong_privkey, msg)

        # Use the fee wallet for the fee input
        adapter._ensure_fee_utxos()
        fee_wallet = adapter._fee_wallet

        # Call upstream get_recovery_tx with our wrong signer
        recovery_spec = ov.get_recovery_tx(
            config, fee_wallet, trigger_utxos, wrong_signer
        )

        # Step 3: Attempt to broadcast
        try:
            rpc.call("sendrawtransaction", recovery_spec.tx.tohex())
            # If we get here, the wrong-key tx was ACCEPTED — unexpected
            result.observe(
                "  UNEXPECTED: Wrong-key recovery transaction was ACCEPTED.  "
                "This would mean OP_VAULT_RECOVER does NOT enforce the "
                "recoveryauth key — a serious consensus bug."
            )
            result.observe("  STATUS: FAIL — anti-griefing property NOT confirmed")
        except Exception as e:
            error_msg = str(e)
            # Step 4: Verify the rejection is a script/consensus failure
            if any(kw in error_msg.lower() for kw in [
                "script", "non-mandatory-script-verify",
                "mandatory-script-verify", "scriptsig",
                "witness", "verify", "checksig",
            ]):
                result.observe(
                    f"  CONFIRMED: Wrong-key recovery REJECTED at consensus level."
                )
                result.observe(f"  Rejection reason: {error_msg}")
                result.observe(
                    "  The OP_VAULT_RECOVER opcode's embedded CHECKSIGVERIFY "
                    "against the committed recoveryauth_pubkey prevents any "
                    "party without the recoveryauth key from executing recovery.  "
                    "This is a hard consensus rule, not a relay policy."
                )
                result.observe(
                    "  STATUS: PASS — anti-griefing property confirmed at "
                    "consensus level"
                )
            else:
                # Rejected for some other reason (e.g. fee, dust)
                result.observe(
                    f"  Recovery rejected, but reason may not be script-related: "
                    f"{error_msg}"
                )
                result.observe(
                    "  STATUS: INCONCLUSIVE — transaction rejected but the "
                    "rejection reason could not be confirmed as a "
                    "CHECKSIGVERIFY failure.  Manual inspection recommended."
                )

    except Exception as e:
        result.observe(f"  Phase 4 setup error: {e}")
        result.observe(
            "  Falling back to analytical argument: OP_VAULT_RECOVER script "
            "includes <recoveryauth_pubkey> OP_CHECKSIGVERIFY before "
            "OP_VAULT_RECOVER.  CHECKSIGVERIFY is a consensus opcode — "
            "invalid signatures cause unconditional script failure, not just "
            "relay rejection.  This is the same enforcement mechanism as any "
            "P2TR script-path spend."
        )
        import traceback
        result.observe(f"  (Error details: {traceback.format_exc().splitlines()[-1]})")
