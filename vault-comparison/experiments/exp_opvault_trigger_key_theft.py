"""Experiment L: OP_VAULT Trigger Key Theft — Structural Differentiators

Analyzes trigger key compromise as it applies specifically to OP_VAULT,
focusing on the structural differences from CTV and CCV rather than
re-demonstrating the generic "trigger → unvault → recovery race" pattern
(which is covered in the lifecycle_costs and recovery_griefing experiments).

=== RELATED WORK ===
BIP-345 §Trigger authorization (https://bips.dev/345/) specifies that the
trigger key is an xpub-derived BIP-32 key, giving OP_VAULT a hierarchical
key structure that CTV (raw hot key) and CCV (raw unvault key) lack.  The
trigger output is a CTV-locked withdrawal — the same finality mechanism as
CTV vaults — meaning OP_VAULT's withdrawal path inherits CTV's timelock
guarantees and its fee-rate estimation challenges.

Harding ("OP_VAULT comments", Delving Bitcoin,
https://delvingbitcoin.org/t/op-vault-comments/521) analyzes trigger key
theft combined with the splitting attack: steal trigger key → split vault
into dust → exhaust watchtower recovery budget → complete withdrawal on
unrecovered UTXOs.  See the watchtower_exhaustion experiment for the
splitting cost model.

O'Beirne (https://jameso.be/vaults.pdf) motivates the general vault design
where a compromised trigger key is recoverable as long as the watchtower is
active.  BIP-345 extends this with the recoveryauth key — a separate
defense layer absent in CTV and CCV.

Swambo et al. ("Custody Protocols Using Bitcoin Vaults", 2020,
https://arxiv.org/abs/2005.11776) formalize the general trigger-key
threat model and identify the two failure conditions: watchtower liveness
failure and fee-budget exhaustion.

=== THREAT MODEL 1: Trigger key compromise (single-key) ===
Attacker: Has the trigger key (xpub-derived).  Does NOT have the
  recoveryauth key.
Goal: Steal vault funds by calling start_withdrawal() with a CTV template
  pointing to the attacker's address.
Defense: Watchtower detects unauthorized trigger and broadcasts
  OP_VAULT_RECOVER (immediate, no timelock).  Recovery requires the
  recoveryauth key (separate from the trigger key).
Outcome: Funds safe if watchtower is active.  Funds lost if watchtower is
  offline for > spend_delay blocks.
Comparison: Structurally identical to CTV hot key theft and CCV unvault
  key theft — the generic pattern.  The differentiator is recovery
  authorization (see below).

=== THREAT MODEL 2: Two-key compromise (trigger + recoveryauth) ===
Attacker: Has BOTH the trigger key AND the recoveryauth key.  Does NOT
  control the recovery address (pre-committed at vault creation).
Goal: Deny vault liveness indefinitely.  The attacker cannot STEAL funds
  because recovery always goes to the pre-committed recovery address
  (owner-controlled).  But the attacker can create a persistent cycle:
    1. Owner deposits into vault → attacker triggers withdrawal
    2. Watchtower (or owner) recovers → funds return to recovery address
    3. Owner re-vaults → attacker triggers again → goto 2
  Each cycle costs the defender trigger + recovery fees.  The attack
  continues until the owner rotates to a fresh vault config with a new
  recoveryauth key.
Cost: One trigger tx per cycle (~T vB).  Attacker does NOT need to
  pay for recovery (the watchtower does).
Payoff: Zero direct financial gain.  Pure liveness denial with fee drain.
Comparison with CCV: CCV has NO recoveryauth key, so the two-key attack
  has no CCV analog.  CCV's equivalent is keyless griefing (lower bar,
  same consequence).
Comparison with CTV: CTV's hot+fee key compromise is MORE dangerous —
  it enables actual fund THEFT via fee pinning (see exp_fee_pinning).
  OP_VAULT's two-key compromise is liveness-only because recovery
  destination is pre-committed.

=== STRUCTURAL DIFFERENTIATORS ===
This experiment measures three things unique to OP_VAULT:
  (a) xpub-derived trigger key: BIP-32 derivation gives path-based key
      management (e.g. m/0h/0 for trigger, rotatable per-vault).
  (b) CTV-locked trigger output: start_withdrawal produces a CTV-committed
      output — the attacker's destination is baked into the template hash,
      making the withdrawal deterministic (same as CTV vaults).
  (c) Separate recoveryauth defense: Recovery requires a DIFFERENT key
      than the trigger key.  Two-key compromise is needed for the worst
      case (persistent liveness denial), unlike CTV where a single hot
      key + fee key combination enables fund theft.

=== EMPIRICAL DEMONSTRATION ===
Phase 1: OP_VAULT-specific trigger mechanics — measure the xpub-derived
  trigger tx and document the CTV-locked output structure.
Phase 2: Standard recovery race (single-key) — confirm watchtower wins.
Phase 3: Two-key compromise simulation — trigger + recoveryauth cycling.
  Measure cumulative cost of the persistent liveness denial.
Phase 4: Structural comparison — tabulate the three differentiators
  across CTV, CCV, and OP_VAULT with measured vsizes.
"""

from adapters.base import VaultAdapter, VaultState, TxRecord
from harness.metrics import ExperimentResult, TxMetrics
from harness.regtest_caveats import emit_regtest_caveats, emit_fee_sensitivity_table
from experiments.registry import register

VAULT_AMOUNT = 49_999_900
TWO_KEY_CYCLES = 3  # repeated trigger→recover cycles for liveness denial


@register(
    name="opvault_trigger_key_theft",
    description="OP_VAULT trigger key theft: structural differentiators and two-key compromise",
    tags=["core", "opvault_specific", "security", "quantitative"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    result = ExperimentResult(
        experiment="opvault_trigger_key_theft",
        covenant=adapter.name,
        params={"vault_amount_sats": VAULT_AMOUNT},
    )

    rpc = adapter.rpc

    if adapter.name != "opvault":
        result.observe(
            f"Skipping opvault_trigger_key_theft on {adapter.name} — "
            "this experiment is OP_VAULT-specific."
        )
        _emit_cross_covenant_note(result, adapter.name)
        return result

    # Fallback vsizes for fee table (replaced by measurements)
    measured_trigger_vsize = 200
    measured_recover_vsize = 170
    measured_withdraw_vsize = 130

    try:
        measured_trigger_vsize, measured_recover_vsize, measured_withdraw_vsize = \
            _run_trigger_key_theft(adapter, result, rpc)
    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")
        import traceback
        result.observe(traceback.format_exc())

    emit_regtest_caveats(
        result,
        experiment_specific=(
            "The recovery race between attacker and watchtower cannot be "
            "demonstrated on regtest (blocks are mined on demand, so there "
            "is no real spend_delay window).  On mainnet, the watchtower has "
            "~10 min × spend_delay blocks to detect and recover.  "
            "The two-key liveness denial cycle IS structurally valid on "
            "regtest — the fee drain is real regardless of block timing.  "
            "CTV-locked output structure and xpub-derived key mechanics are "
            "consensus-level properties, identical on regtest and mainnet."
        ),
    )
    emit_fee_sensitivity_table(
        result,
        threat_model_name="Trigger key theft (single-key + two-key)",
        vsize_rows=[
            {"label": "attacker_trigger", "vsize": measured_trigger_vsize,
             "description": "start_withdrawal to attacker CTV destination"},
            {"label": "watchtower_recovery", "vsize": measured_recover_vsize,
             "description": "OP_VAULT_RECOVER (needs recoveryauth key)"},
            {"label": "attacker_withdrawal", "vsize": measured_withdraw_vsize,
             "description": "CTV-locked final withdrawal (if no recovery)"},
        ],
        vault_amount_sats=VAULT_AMOUNT,
    )

    return result


def _run_trigger_key_theft(adapter, result, rpc):
    """Execute the trigger key theft analysis.

    Returns (trigger_vsize, recover_vsize, withdraw_vsize) for fee table.
    """

    # ── Phase 1: OP_VAULT trigger mechanics ────────────────────────────
    result.observe("=== Phase 1: OP_VAULT-specific trigger mechanics ===")
    result.observe(
        "OP_VAULT's trigger key is an xpub-derived BIP-32 key (not a raw key "
        "like CTV's hot key or CCV's unvault key).  This gives hierarchical "
        "key management: derive per-vault trigger keys from a single xpub, "
        "rotate without changing the master."
    )

    vault = adapter.create_vault(VAULT_AMOUNT)
    result.observe(
        f"Vault created: {vault.vault_txid[:16]}... ({vault.amount_sats:,} sats)"
    )

    # Document the key structure from the vault config
    config = vault.extra["config"]
    result.observe(
        f"  trigger_xpub: {config.trigger_xpub[:24]}... (BIP-32 extended pubkey)"
    )
    result.observe(
        f"  recoveryauth_pubkey: {config.recoveryauth_pubkey.hex()[:24]}... "
        f"(separate Schnorr key)"
    )
    result.observe(
        f"  recovery_pubkey: {config.recovery_pubkey.hex()[:24]}... "
        f"(pre-committed destination — NOT derivable from trigger or recoveryauth)"
    )
    result.observe(
        f"  spend_delay: {config.spend_delay} blocks (CSV timelock on trigger output)"
    )
    result.observe(
        "  KEY SEPARATION: Three distinct keys.  Compromising the trigger key "
        "alone is insufficient for theft (need watchtower offline) and "
        "insufficient for recovery griefing (need recoveryauth key)."
    )

    # Trigger and measure the CTV-locked output
    unvault = adapter.trigger_unvault(vault)
    trigger_info = rpc.get_tx_info(unvault.unvault_txid)
    trigger_vsize = trigger_info["vsize"]
    trigger_fee = rpc.get_tx_fee_sats(unvault.unvault_txid)
    result.observe(
        f"\n  Trigger tx (start_withdrawal): vsize={trigger_vsize}, "
        f"fee={trigger_fee} sats"
    )
    result.observe(
        "  The trigger output is CTV-LOCKED: the withdrawal destination is "
        "committed via OP_CHECKTEMPLATEVERIFY inside the taproot script.  "
        "This is the same finality mechanism as CTV vaults — the attacker "
        "must pre-commit to a specific destination at trigger time."
    )
    result.add_tx(TxMetrics(
        label="phase1_trigger",
        txid=unvault.unvault_txid,
        vsize=trigger_vsize,
        weight=trigger_info["weight"],
        fee_sats=trigger_fee,
        num_inputs=len(trigger_info["vin"]),
        num_outputs=len(trigger_info["vout"]),
        amount_sats=unvault.amount_sats,
    ))

    # ── Phase 2: Single-key recovery race ──────────────────────────────
    result.observe("\n=== Phase 2: Single-key theft — watchtower recovery race ===")
    result.observe(
        "Standard scenario: attacker has trigger key only.  Watchtower "
        "detects unauthorized trigger and races to recover."
    )

    # Watchtower recovers
    recover_record = adapter.recover(unvault)
    recover_metrics = adapter.collect_tx_metrics(recover_record, rpc)
    recover_vsize = recover_metrics.vsize
    recover_fee = recover_metrics.fee_sats
    result.observe(
        f"  Watchtower recovery: vsize={recover_vsize}, fee={recover_fee} sats"
    )
    result.add_tx(recover_metrics)

    result.observe(
        "  RESULT: Funds recovered to pre-committed recovery address.  "
        "Attack fails.  This is the standard outcome shared by all three "
        "covenant designs when the watchtower is active."
    )

    # Measure withdrawal (undefended case) for fee table
    vault2 = adapter.create_vault(VAULT_AMOUNT)
    unvault2 = adapter.trigger_unvault(vault2)
    withdraw_record = adapter.complete_withdrawal(unvault2, path="hot")
    withdraw_metrics = adapter.collect_tx_metrics(withdraw_record, rpc)
    withdraw_vsize = withdraw_metrics.vsize or 130

    result.observe(
        f"  (Undefended withdrawal measured for fee table: {withdraw_vsize} vB)"
    )

    # ── Phase 3: Two-key compromise — persistent liveness denial ───────
    result.observe(
        f"\n=== Phase 3: Two-key compromise — liveness denial "
        f"({TWO_KEY_CYCLES} cycles) ==="
    )
    result.observe(
        "Scenario: Attacker has BOTH the trigger key AND the recoveryauth "
        "key.  Cannot steal funds (recovery destination is pre-committed to "
        "the owner's address).  Instead, creates a persistent denial cycle:"
    )
    result.observe(
        "  1. Owner vaults funds → attacker triggers withdrawal"
    )
    result.observe(
        "  2. Attacker OR watchtower recovers → funds go to owner's recovery addr"
    )
    result.observe(
        "  3. Owner re-vaults (must, to use funds) → attacker triggers again"
    )
    result.observe(
        "  Each cycle costs the DEFENDER at least one trigger + one recovery "
        "in fees.  The attacker pays only for the trigger."
    )

    # Why this has no CCV analog
    result.observe(
        "\n  WHY THIS IS OP_VAULT-SPECIFIC: CCV recovery is keyless — "
        "there's no second key to compromise.  CCV's equivalent is the "
        "keyless griefing attack (recovery_griefing experiment), which "
        "requires NO keys but has the same consequence.  The two-key "
        "compromise is unique to OP_VAULT's authorized recovery design."
    )

    attacker_cumulative_vsize = 0
    defender_cumulative_vsize = 0
    cycles_completed = 0

    for cycle in range(1, TWO_KEY_CYCLES + 1):
        try:
            # Owner creates vault (or re-vaults after previous recovery)
            v = adapter.create_vault(VAULT_AMOUNT)

            # Attacker triggers withdrawal (has trigger key)
            uv = adapter.trigger_unvault(v)
            t_info = rpc.get_tx_info(uv.unvault_txid)
            t_vsize = t_info.get("vsize", trigger_vsize)

            # Attacker races watchtower to recover (has recoveryauth key)
            # Both go to the same pre-committed address — attacker gains nothing
            # but forces the cycle to repeat
            r_record = adapter.recover(uv)
            r_metrics = adapter.collect_tx_metrics(r_record, rpc)
            r_vsize = r_metrics.vsize or recover_vsize

            attacker_cumulative_vsize += t_vsize  # attacker pays trigger
            defender_cumulative_vsize += r_vsize   # defender pays recovery
            # (In practice the attacker might also pay recovery to force the
            # race, but the defender always pays at least the re-vault cost)
            cycles_completed = cycle

            result.observe(
                f"  Cycle {cycle}: trigger={t_vsize} vB (attacker), "
                f"recover={r_vsize} vB (either)  |  "
                f"Cumulative: attacker={attacker_cumulative_vsize} vB, "
                f"defender={defender_cumulative_vsize} vB"
            )

        except Exception as e:
            result.observe(f"  Cycle {cycle}: FAILED — {e}")
            break

    if cycles_completed > 0 and attacker_cumulative_vsize > 0:
        result.observe(
            f"\n  After {cycles_completed} cycles: attacker spent "
            f"{attacker_cumulative_vsize} vB on triggers, defender spent "
            f"{defender_cumulative_vsize} vB on recoveries."
        )
        # Project to exhaustion
        result.observe("\n  --- Liveness denial cost projection ---")
        result.observe(
            "  fee_rate  |  attacker/cycle  |  defender/cycle  |  "
            "10-cycle attacker  |  10-cycle defender"
        )
        result.observe(
            "  ---------+-----------------+-----------------+"
            "-------------------+------------------"
        )
        avg_atk_vsize = attacker_cumulative_vsize // cycles_completed
        avg_def_vsize = defender_cumulative_vsize // cycles_completed
        for fee_rate in [1, 10, 50, 100, 500]:
            atk_per = avg_atk_vsize * fee_rate
            def_per = avg_def_vsize * fee_rate
            result.observe(
                f"  {fee_rate:>3} s/vB  |  {atk_per:>11,} sats  |  "
                f"{def_per:>11,} sats  |  {atk_per * 10:>13,} sats  |  "
                f"{def_per * 10:>12,} sats"
            )

        result.observe(
            "\n  DEFENSE: Owner must rotate to a new vault config with a fresh "
            "recoveryauth key.  The attacker's trigger key also needs rotation "
            "(new xpub).  Until rotation completes, the attacker can sustain "
            "the denial cycle at ~trigger_vsize × fee_rate per round."
        )
        result.observe(
            "  COMPARISON WITH CTV: CTV hot key + fee key compromise enables "
            "actual FUND THEFT (via fee pinning → descendant chain → block "
            "cold sweep).  OP_VAULT two-key compromise is strictly liveness "
            "denial — funds ALWAYS go to the pre-committed recovery address.  "
            "This is a direct consequence of BIP-345's pre-committed recovery "
            "destination design."
        )

    # ── Phase 4: Structural comparison table ───────────────────────────
    result.observe(
        "\n=== Phase 4: Cross-covenant structural comparison ==="
    )
    result.observe(
        "Three features distinguish OP_VAULT's trigger key theft from "
        "CTV's and CCV's equivalent attacks:"
    )

    result.observe("\n  (a) KEY DERIVATION:")
    result.observe(
        "      CTV:      Raw hot key (single scalar).  No hierarchy."
    )
    result.observe(
        "      CCV:      Raw unvault key (single scalar).  No hierarchy."
    )
    result.observe(
        "      OP_VAULT: xpub-derived BIP-32 key.  Per-vault derivation "
        "paths (m/0h/N), rotatable from master without changing vault "
        "config structure."
    )

    result.observe("\n  (b) TRIGGER OUTPUT STRUCTURE:")
    result.observe(
        "      CTV:      CTV-locked output (OP_CHECKTEMPLATEVERIFY).  "
        "Destination pre-committed in template hash."
    )
    result.observe(
        "      CCV:      CCV-locked output (OP_CHECKCONTRACTVERIFY).  "
        "Destination committed in contract state."
    )
    result.observe(
        f"      OP_VAULT: CTV-locked output (same as CTV).  "
        f"Measured trigger: {trigger_vsize} vB.  "
        "Withdrawal inherits CTV's finality guarantees AND its "
        "fee-rate estimation challenges."
    )

    result.observe("\n  (c) RECOVERY AUTHORIZATION:")
    result.observe(
        "      CTV:      Cold key sweep (tocold tx).  Keyed recovery."
    )
    result.observe(
        "      CCV:      Keyless recovery (anyone can trigger).  "
        "Enables anonymous griefing."
    )
    result.observe(
        f"      OP_VAULT: Authorized recovery (recoveryauth key).  "
        f"Measured: {recover_vsize} vB.  "
        "Blocks anonymous griefing but creates a second key to protect."
    )

    result.observe("\n  WORST-CASE KEY COMPROMISE:")
    result.observe(
        "      CTV:      hot key + fee key → FUND THEFT (fee pinning attack)"
    )
    result.observe(
        "      CCV:      unvault key → LIVENESS DENIAL (anyone can also grief)"
    )
    result.observe(
        "      OP_VAULT: trigger key + recoveryauth key → LIVENESS DENIAL ONLY "
        "(funds safe in pre-committed recovery address)"
    )
    result.observe(
        "  OP_VAULT's worst-case two-key compromise is strictly less severe "
        "than CTV's: liveness denial vs fund theft.  This is the key "
        "security advantage of the pre-committed recovery address design."
    )

    # ── Summary ──────────────────────────────────────────────────────
    result.observe("\n=== Summary ===")
    result.observe(
        "OP_VAULT trigger key theft is structurally similar to CTV and CCV "
        "but differs in three measurable ways: (a) xpub-derived key hierarchy, "
        "(b) CTV-locked trigger output (shared with CTV, distinct from CCV), "
        "and (c) separate recoveryauth defense layer."
    )
    result.observe(
        "The OP_VAULT-specific two-key compromise (trigger + recoveryauth) "
        "creates a persistent liveness denial cycle but CANNOT escalate to "
        "fund theft because the recovery destination is pre-committed.  "
        "This contrasts with CTV where hot key + fee key compromise enables "
        "irrecoverable fund theft via fee pinning."
    )
    result.observe(
        "CROSS-EXPERIMENT REFERENCES: See recovery_griefing for the CCV "
        "keyless equivalent; opvault_recovery_auth for the recoveryauth "
        "compromise analysis; fee_pinning for CTV's escalation to theft; "
        "watchtower_exhaustion for the splitting amplification attack."
    )

    return (trigger_vsize, recover_vsize, withdraw_vsize)


def _emit_cross_covenant_note(result, covenant_name):
    """Emit a note explaining what this experiment covers for non-OP_VAULT covenants."""
    if covenant_name == "ctv":
        result.observe(
            "CTV EQUIVALENT: Hot key compromise → tocold sweep race.  "
            "Combined with fee key → fee pinning → fund THEFT.  "
            "See exp_fee_pinning for the CTV-specific attack chain.  "
            "CTV's worst case is MORE severe than OP_VAULT's (theft vs denial)."
        )
    elif covenant_name == "ccv":
        result.observe(
            "CCV EQUIVALENT: Unvault key compromise → keyless recovery race.  "
            "No second key needed — anyone can grief recovery.  "
            "See exp_recovery_griefing for the CCV-specific analysis.  "
            "CCV's single-key attack has the same consequence (liveness denial) "
            "at a LOWER attacker bar (no recoveryauth key needed)."
        )
    else:
        result.observe(
            f"No trigger key theft analysis available for {covenant_name}."
        )
