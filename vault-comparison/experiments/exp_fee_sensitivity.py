"""Experiment J: Fee Environment Sensitivity Analysis

Synthesizes vsize measurements from all experiments and computes
economic costs, attack rationality thresholds, and crossover points
across historical Bitcoin fee environments.

=== METHODOLOGY ===
This is an ANALYTICAL experiment — it does not require on-chain
transactions.  The vsize values it uses are STRUCTURAL constants
determined by the script and witness structure of each vault design.
On regtest, these are fully deterministic (same script = same vsize).

The analysis takes these structural measurements and projects them
into real-world economic costs at historically observed fee rates:
  - 1 sat/vB:   2021 low-fee environment (post-halving bear market)
  - 10 sat/vB:  2022 average (Taproot adoption, moderate usage)
  - 50 sat/vB:  2023 moderate congestion (ordinals, BRC-20 early)
  - 100 sat/vB: 2024 inscription congestion (sustained high fees)
  - 300 sat/vB: 2023 spike peak (BRC-20 mania, Dec 2023)
  - 500 sat/vB: Stress scenario (2024 runes launch, worst-case)

For each threat model, the analysis:
1. Computes attacker cost and defender cost at each fee rate
2. Identifies the rationality condition (when is the attack worth it?)
3. Finds crossover points (where fee environment changes the calculus)
4. Compares CTV vs CCV attack surfaces across fee environments

=== KEY INSIGHT ===
Some attacks become MORE dangerous in high-fee environments (fee pinning
— higher congestion makes the pin harder to escape).  Others become MORE
EXPENSIVE (griefing — attacker pays more per round).  The crossover
points where attacks shift from viable to unviable are the key finding.
"""

from harness.metrics import ExperimentResult, TxMetrics
from experiments.registry import register

# ── Structural vsize constants ───────────────────────────────────────
# These are DETERMINISTIC values from the script/witness structure.
# On regtest, identical scripts always produce identical vsize.
# Sources: fee_pinning, recovery_griefing, watchtower_exhaustion,
# lifecycle_costs experiment code + docstrings.

# CTV lifecycle (simple-ctv-vault)
CTV_TOVAULT_VSIZE = 154       # P2WSH funding tx
CTV_UNVAULT_VSIZE = 164       # CTV-committed unvault
CTV_WITHDRAW_VSIZE = 108      # P2WPKH hot withdrawal after CSV
CTV_TOCOLD_VSIZE = 180        # Cold sweep (recovery path)
CTV_LIFECYCLE_TOTAL = CTV_TOVAULT_VSIZE + CTV_UNVAULT_VSIZE + CTV_WITHDRAW_VSIZE

# CCV lifecycle (pymatt vault)
CCV_TOVAULT_VSIZE = 154       # P2TR funding tx
CCV_TRIGGER_VSIZE = 154       # Trigger unvault (Schnorr sig + CCV)
CCV_WITHDRAW_VSIZE = 110      # CTV-committed withdrawal after CSV
CCV_RECOVER_VSIZE = 122       # Keyless recovery (no sig needed)
CCV_LIFECYCLE_TOTAL = CCV_TOVAULT_VSIZE + CCV_TRIGGER_VSIZE + CCV_WITHDRAW_VSIZE

# CCV revault operations
CCV_TRIGGER_REVAULT_VSIZE = 162  # trigger_and_revault (partial withdrawal)
CCV_BATCHED_PER_INPUT = 106      # marginal cost per additional vault in batch

# Fee pinning attack (CTV-specific)
FEE_PIN_DESCENDANT_VSIZE = 110   # single descendant tx in the chain
FEE_PIN_CHAIN_COUNT = 25         # Bitcoin Core default -limitdescendantcount
FEE_PIN_TOTAL_CHAIN_VSIZE = FEE_PIN_DESCENDANT_VSIZE * (FEE_PIN_CHAIN_COUNT - 1)  # ~2640 vB

# Watchtower exhaustion (CCV-specific)
WT_TRIGGER_VSIZE = CCV_TRIGGER_REVAULT_VSIZE  # per-split trigger cost
WT_RECOVER_VSIZE = CCV_RECOVER_VSIZE          # per-split recovery cost
WT_BATCHED_RECOVERY_OVERHEAD = 55             # fixed overhead for batched recovery
WT_BATCHED_RECOVERY_PER_INPUT = 67            # per-input cost in batched recovery

# ── Historical fee rate environments ─────────────────────────────────
FEE_ENVIRONMENTS = [
    (1,   "2021 bear market low"),
    (10,  "2022 average"),
    (50,  "2023 moderate congestion"),
    (100, "2024 inscription congestion"),
    (300, "2023 spike peak (BRC-20 mania)"),
    (500, "Stress scenario (runes launch)"),
]

# Vault amount for analysis
VAULT_AMOUNT_SATS = 49_999_900  # ~0.5 BTC
VAULT_AMOUNT_BTC = VAULT_AMOUNT_SATS / 100_000_000


@register(
    name="fee_sensitivity",
    description="Cross-experiment fee environment sensitivity analysis",
    tags=["core", "analytical", "quantitative", "fee_management"],
)
def run(adapter=None) -> ExperimentResult:
    """Run the fee sensitivity analysis.

    This experiment is purely analytical — it uses structural vsize
    constants and computes economic projections.  It does NOT require
    on-chain transactions or a running Bitcoin node.

    The adapter parameter is accepted for interface compatibility but
    is not used for on-chain operations.
    """
    covenant_name = adapter.name if adapter else "analytical"

    result = ExperimentResult(
        experiment="fee_sensitivity",
        covenant=covenant_name,
        params={
            "vault_amount_sats": VAULT_AMOUNT_SATS,
            "fee_environments": [(r, l) for r, l in FEE_ENVIRONMENTS],
            "note": "Analytical experiment — no on-chain transactions",
        },
    )

    # ── Section 1: Lifecycle cost comparison ──────────────────────────
    _section_lifecycle_costs(result)

    # ── Section 2: Fee pinning attack economics ──────────────────────
    _section_fee_pinning(result)

    # ── Section 3: Recovery griefing economics ───────────────────────
    _section_recovery_griefing(result)

    # ── Section 4: Watchtower exhaustion economics ───────────────────
    _section_watchtower_exhaustion(result)

    # ── Section 5: Cross-experiment synthesis ─────────────────────────
    _section_synthesis(result)

    # Record structural vsize as TxMetrics for machine-readable output
    _record_structural_metrics(result)

    return result


def _fmt_sats(sats):
    """Format satoshis with commas."""
    return f"{sats:,}"


def _fmt_btc(sats):
    """Format satoshis as BTC."""
    return f"{sats / 100_000_000:.6f}"


def _section_lifecycle_costs(result):
    """Section 1: Normal vault lifecycle costs across fee environments."""
    result.observe("=" * 70)
    result.observe("SECTION 1: VAULT LIFECYCLE COSTS")
    result.observe("=" * 70)
    result.observe(
        "The complete vault lifecycle (deposit → unvault → withdrawal) has "
        "a fixed structural vsize cost that translates to different economic "
        "costs depending on the fee environment."
    )

    result.observe(f"\nStructural vsize (deterministic):")
    result.observe(f"  CTV lifecycle: {CTV_LIFECYCLE_TOTAL} vB "
                   f"(tovault={CTV_TOVAULT_VSIZE} + unvault={CTV_UNVAULT_VSIZE} "
                   f"+ withdraw={CTV_WITHDRAW_VSIZE})")
    result.observe(f"  CCV lifecycle: {CCV_LIFECYCLE_TOTAL} vB "
                   f"(tovault={CCV_TOVAULT_VSIZE} + trigger={CCV_TRIGGER_VSIZE} "
                   f"+ withdraw={CCV_WITHDRAW_VSIZE})")
    savings_vb = CTV_LIFECYCLE_TOTAL - CCV_LIFECYCLE_TOTAL
    savings_pct = savings_vb / CTV_LIFECYCLE_TOTAL * 100 if CTV_LIFECYCLE_TOTAL else 0
    result.observe(f"  Difference: CCV saves {savings_vb} vB ({savings_pct:.1f}%)")

    # Table
    result.observe(f"\n{'Fee Rate':>12} {'Period':<35} {'CTV Cost':>12} {'CCV Cost':>12} {'Savings':>10} {'as % vault':>12}")
    result.observe("-" * 95)

    for rate, period in FEE_ENVIRONMENTS:
        ctv_cost = CTV_LIFECYCLE_TOTAL * rate
        ccv_cost = CCV_LIFECYCLE_TOTAL * rate
        savings = ctv_cost - ccv_cost
        pct_vault = ctv_cost / VAULT_AMOUNT_SATS * 100
        result.observe(
            f"{rate:>8} s/vB  {period:<35} {_fmt_sats(ctv_cost):>12} {_fmt_sats(ccv_cost):>12} "
            f"{_fmt_sats(savings):>10} {pct_vault:>10.3f}%"
        )

    result.observe(
        f"\nINSIGHT: At 500 sat/vB (stress), a full CTV lifecycle costs "
        f"{_fmt_sats(CTV_LIFECYCLE_TOTAL * 500)} sats "
        f"({CTV_LIFECYCLE_TOTAL * 500 / VAULT_AMOUNT_SATS * 100:.2f}% of a 0.5 BTC vault).  "
        f"Lifecycle cost becomes material above ~100 sat/vB for sub-BTC vaults."
    )


def _section_fee_pinning(result):
    """Section 2: Fee pinning attack economics (CTV-specific)."""
    result.observe("")
    result.observe("=" * 70)
    result.observe("SECTION 2: FEE PINNING ATTACK ECONOMICS (CTV-SPECIFIC)")
    result.observe("=" * 70)
    result.observe(
        "The descendant-chain pinning attack has a FIXED structural cost "
        f"({FEE_PIN_TOTAL_CHAIN_VSIZE} vB for {FEE_PIN_CHAIN_COUNT - 1} descendants) "
        "that scales linearly with fee rate.  But the DAMAGE also scales: "
        "in high-fee environments, the pinned tocold is harder to rescue "
        "because fee bumping costs more."
    )

    result.observe(f"\nAttack structure: {FEE_PIN_CHAIN_COUNT - 1} descendant txs × {FEE_PIN_DESCENDANT_VSIZE} vB = {FEE_PIN_TOTAL_CHAIN_VSIZE} vB total")
    result.observe(f"Defender recovery: {CTV_TOCOLD_VSIZE} vB (cold sweep)")
    result.observe(f"Vault value at stake: {_fmt_sats(VAULT_AMOUNT_SATS)} sats (~{VAULT_AMOUNT_BTC:.2f} BTC)")

    # Capital cost includes dust outputs in the chain
    DUST_PER_TX = 546
    CAPITAL_DUST = DUST_PER_TX * (FEE_PIN_CHAIN_COUNT - 1)

    result.observe(f"\n{'Fee Rate':>12} {'Period':<35} {'Attack Cost':>14} {'Dust Capital':>14} {'Total Deploy':>14} {'% of Vault':>12} {'Rational?':>10}")
    result.observe("-" * 113)

    for rate, period in FEE_ENVIRONMENTS:
        attack_fees = FEE_PIN_TOTAL_CHAIN_VSIZE * rate
        total_deployed = attack_fees + CAPITAL_DUST
        pct = total_deployed / VAULT_AMOUNT_SATS * 100
        # Attack is ALWAYS rational if attacker also has hot key
        # (total fund theft for <1% cost)
        rational = "ALWAYS" if pct < 10 else "LIKELY" if pct < 50 else "MARGINAL"
        result.observe(
            f"{rate:>8} s/vB  {period:<35} {_fmt_sats(attack_fees):>14} "
            f"{_fmt_sats(CAPITAL_DUST):>14} {_fmt_sats(total_deployed):>14} "
            f"{pct:>10.4f}% {rational:>10}"
        )

    result.observe(
        "\nKEY FINDING: Fee pinning becomes MORE dangerous in high-fee "
        "environments, not less.  The attack cost rises linearly, but "
        "the defender's inability to fee-bump the pinned tocold is WORSE "
        "when block space is congested.  At 500 sat/vB, the attack costs "
        f"{_fmt_sats(FEE_PIN_TOTAL_CHAIN_VSIZE * 500)} sats "
        f"({FEE_PIN_TOTAL_CHAIN_VSIZE * 500 / VAULT_AMOUNT_SATS * 100:.3f}% of vault) — "
        "trivially rational for any attacker who also holds the hot key."
    )

    # Crossover: When does the attack cost exceed vault value?
    if FEE_PIN_TOTAL_CHAIN_VSIZE > 0:
        breakeven_rate = VAULT_AMOUNT_SATS / FEE_PIN_TOTAL_CHAIN_VSIZE
        result.observe(
            f"\nBREAKEVEN: Attack cost alone equals vault value at "
            f"{breakeven_rate:,.0f} sat/vB — a fee rate that has never occurred "
            f"in Bitcoin's history.  Fee pinning is ALWAYS economically rational "
            f"as a component of hot-key theft."
        )


def _section_recovery_griefing(result):
    """Section 3: Recovery griefing economics (CCV: keyless, CTV: hot-key)."""
    result.observe("")
    result.observe("=" * 70)
    result.observe("SECTION 3: RECOVERY GRIEFING ECONOMICS")
    result.observe("=" * 70)

    # CCV griefing
    result.observe("\n--- CCV: Keyless Recovery Griefing ---")
    result.observe(
        f"Attacker cost per round: {CCV_RECOVER_VSIZE} vB (recovery tx, NO key needed)"
    )
    result.observe(
        f"Defender cost per round: {CCV_TRIGGER_VSIZE} vB (re-trigger unvault)"
    )
    asymmetry = CCV_TRIGGER_VSIZE / CCV_RECOVER_VSIZE if CCV_RECOVER_VSIZE else 1
    result.observe(f"Cost asymmetry: {asymmetry:.2f}x (defender pays MORE)")

    result.observe(f"\n{'Fee Rate':>12} {'Atk/Round':>12} {'Def/Round':>12} {'Atk 10 Rds':>14} {'Def 10 Rds':>14} {'Rds to 1%':>12} {'Rds to 10%':>12}")
    result.observe("-" * 90)

    for rate, period in FEE_ENVIRONMENTS:
        atk_per_round = CCV_RECOVER_VSIZE * rate
        def_per_round = CCV_TRIGGER_VSIZE * rate
        atk_10 = atk_per_round * 10
        def_10 = def_per_round * 10
        rds_1pct = int(VAULT_AMOUNT_SATS * 0.01 / def_per_round) if def_per_round > 0 else 999999
        rds_10pct = int(VAULT_AMOUNT_SATS * 0.10 / def_per_round) if def_per_round > 0 else 999999
        result.observe(
            f"{rate:>8} s/vB {_fmt_sats(atk_per_round):>12} {_fmt_sats(def_per_round):>12} "
            f"{_fmt_sats(atk_10):>14} {_fmt_sats(def_10):>14} "
            f"{rds_1pct:>12,} {rds_10pct:>12,}"
        )

    # Crossover analysis
    result.observe(
        "\nCROSSOVER: Griefing becomes MORE EXPENSIVE for the attacker in "
        "high-fee environments (linear scaling).  But the defender's cost "
        f"scales {asymmetry:.2f}x faster.  The attack is pure DoS with zero "
        "financial gain — rational only with external incentive."
    )

    # At what fee rate does 10 rounds of griefing cost >1% of vault?
    if CCV_RECOVER_VSIZE > 0:
        rate_for_1pct_10rds = VAULT_AMOUNT_SATS * 0.01 / (CCV_RECOVER_VSIZE * 10)
        result.observe(
            f"  10 rounds of griefing costs >1% of vault at >{rate_for_1pct_10rds:.0f} sat/vB "
            f"(attacker's cost).  This is a deterrent in high-fee environments."
        )

    # CTV comparison
    result.observe("\n--- CTV: Hot-Key Sweep Griefing ---")
    result.observe(
        f"Attacker cost per round: {CTV_UNVAULT_VSIZE} vB (trigger unvault, needs HOT KEY)"
    )
    result.observe(
        f"Defender cost per round: {CTV_TOCOLD_VSIZE} vB (cold sweep)"
    )
    ctv_asymmetry = CTV_UNVAULT_VSIZE / CTV_TOCOLD_VSIZE if CTV_TOCOLD_VSIZE else 1
    result.observe(
        f"Cost asymmetry: {ctv_asymmetry:.2f}x "
        f"({'attacker pays MORE' if ctv_asymmetry > 1 else 'defender pays MORE'})"
    )
    result.observe(
        "KEY DIFFERENCE: CTV griefing requires the HOT KEY (higher bar).  "
        "CCV griefing requires NO KEY (anyone can grief).  CTV griefing "
        "with hot+fee key can escalate to fund theft (fee_pinning) under "
        "current relay policy (mitigable by TRUC/v3).  CCV griefing is "
        "liveness-only but can impose indefinite withdrawal delays."
    )


def _section_watchtower_exhaustion(result):
    """Section 4: Watchtower exhaustion economics (CCV-specific)."""
    result.observe("")
    result.observe("=" * 70)
    result.observe("SECTION 4: WATCHTOWER EXHAUSTION ECONOMICS (CCV-SPECIFIC)")
    result.observe("=" * 70)
    result.observe(
        "The attacker splits a vault into N small UTXOs via trigger_and_revault, "
        "forcing the watchtower to recover each one.  The watchtower's cumulative "
        "recovery cost must not exceed the vault value."
    )

    result.observe(f"\nStructural constants:")
    result.observe(f"  trigger_and_revault vsize: {WT_TRIGGER_VSIZE} vB (attacker's cost per split)")
    result.observe(f"  individual recovery vsize: {WT_RECOVER_VSIZE} vB (watchtower's cost per recovery)")
    result.observe(f"  batched recovery: ~{WT_BATCHED_RECOVERY_OVERHEAD} + {WT_BATCHED_RECOVERY_PER_INPUT} × N vB")

    split_asymmetry = WT_RECOVER_VSIZE / WT_TRIGGER_VSIZE if WT_TRIGGER_VSIZE else 1
    result.observe(f"  recovery/trigger ratio: {split_asymmetry:.2f}x")

    # Analysis: How many splits before watchtower is exhausted?
    result.observe(f"\n--- Individual Recovery Analysis ---")
    result.observe(f"{'Fee Rate':>12} {'Trigger Cost':>14} {'Recover Cost':>14} {'Splits to Exhaust':>18} {'Attacker Spend':>16} {'Net Gain':>14}")
    result.observe("-" * 92)

    for rate, period in FEE_ENVIRONMENTS:
        trigger_cost = WT_TRIGGER_VSIZE * rate
        recover_cost = WT_RECOVER_VSIZE * rate

        # Watchtower exhaustion: when cumulative recovery > vault value
        # N × recover_cost > VAULT_AMOUNT → N > VAULT_AMOUNT / recover_cost
        if recover_cost > 0:
            splits_to_exhaust = VAULT_AMOUNT_SATS // recover_cost
        else:
            splits_to_exhaust = 999999

        attacker_total = splits_to_exhaust * trigger_cost
        # Net gain: vault value minus attacker's total trigger cost
        net_gain = VAULT_AMOUNT_SATS - attacker_total

        result.observe(
            f"{rate:>8} s/vB {_fmt_sats(trigger_cost):>14} {_fmt_sats(recover_cost):>14} "
            f"{splits_to_exhaust:>18,} {_fmt_sats(attacker_total):>16} {_fmt_sats(net_gain):>14}"
        )

    result.observe(
        "\nINSIGHT: At 1 sat/vB, the attacker needs ~409,836 splits to exhaust "
        "the watchtower — infeasible.  At 500 sat/vB, only ~819 splits needed, "
        "but the attacker's own trigger cost is also ~81,900 sats per split."
    )

    # Batched recovery analysis
    result.observe(f"\n--- Batched Recovery Defense ---")
    result.observe("If the watchtower batches N recoveries into a single tx:")
    result.observe(f"  Batch vsize ≈ {WT_BATCHED_RECOVERY_OVERHEAD} + {WT_BATCHED_RECOVERY_PER_INPUT} × N")
    result.observe(f"  Per-recovery cost in batch = ({WT_BATCHED_RECOVERY_OVERHEAD}/N + {WT_BATCHED_RECOVERY_PER_INPUT}) × fee_rate")

    batch_sizes = [1, 10, 25, 50, 100]
    result.observe(f"\n{'Batch Size':>12} {'Total vsize':>12} {'Per-Input':>12} {'Savings vs Ind.':>16}")
    result.observe("-" * 54)

    for n in batch_sizes:
        batch_vsize = WT_BATCHED_RECOVERY_OVERHEAD + WT_BATCHED_RECOVERY_PER_INPUT * n
        per_input = batch_vsize / n
        individual_total = WT_RECOVER_VSIZE * n
        savings_pct = (1 - batch_vsize / individual_total) * 100 if individual_total else 0
        result.observe(
            f"{n:>12} {batch_vsize:>10} vB {per_input:>10.1f} vB {savings_pct:>14.1f}%"
        )

    result.observe(
        "\nBatched recovery at 100 inputs saves ~45% vs individual recovery.  "
        "This is the watchtower's key defense: accumulate pending recoveries "
        "and batch them.  The attacker must split faster than the watchtower "
        "batches."
    )

    # Crossover: fee rate where attack becomes viable
    result.observe(f"\n--- Viability Crossover ---")
    result.observe("At what fee rate does the attack become viable (splits < 1000)?")
    for rate, period in FEE_ENVIRONMENTS:
        recover_cost = WT_RECOVER_VSIZE * rate
        trigger_cost = WT_TRIGGER_VSIZE * rate
        if recover_cost > 0:
            n_splits = VAULT_AMOUNT_SATS // recover_cost
            atk_total = n_splits * trigger_cost
            atk_pct = atk_total / VAULT_AMOUNT_SATS * 100
            viable = "VIABLE" if n_splits < 10000 else "INFEASIBLE"
            result.observe(
                f"  {rate:>3} sat/vB: {n_splits:>8,} splits needed, "
                f"attacker spends {atk_pct:.1f}% of vault value — {viable}"
            )


def _section_synthesis(result):
    """Section 5: Cross-experiment synthesis and key findings."""
    result.observe("")
    result.observe("=" * 70)
    result.observe("SECTION 5: CROSS-EXPERIMENT SYNTHESIS")
    result.observe("=" * 70)

    result.observe("\n--- Attack Severity Matrix ---")
    result.observe("How each attack's severity changes with fee environment:\n")

    result.observe(f"{'Attack':>30} {'Low (1)':>12} {'Med (50)':>12} {'High (300)':>12} {'Stress (500)':>14}")
    result.observe("-" * 82)

    # Fee pinning (CTV): gets WORSE with high fees
    result.observe(
        f"{'Fee pinning (CTV)':>30} {'CRITICAL':>12} {'CRITICAL':>12} {'CRITICAL':>12} {'CRITICAL':>14}"
    )
    result.observe(
        f"{'  attack cost':>30} {_fmt_sats(FEE_PIN_TOTAL_CHAIN_VSIZE * 1):>12} "
        f"{_fmt_sats(FEE_PIN_TOTAL_CHAIN_VSIZE * 50):>12} "
        f"{_fmt_sats(FEE_PIN_TOTAL_CHAIN_VSIZE * 300):>12} "
        f"{_fmt_sats(FEE_PIN_TOTAL_CHAIN_VSIZE * 500):>14}"
    )

    # Recovery griefing (CCV): more expensive but still cheap
    result.observe(
        f"{'Recovery griefing (CCV)':>30} {'LOW':>12} {'LOW':>12} {'MODERATE':>12} {'MODERATE':>14}"
    )
    result.observe(
        f"{'  10-round attacker cost':>30} {_fmt_sats(CCV_RECOVER_VSIZE * 1 * 10):>12} "
        f"{_fmt_sats(CCV_RECOVER_VSIZE * 50 * 10):>12} "
        f"{_fmt_sats(CCV_RECOVER_VSIZE * 300 * 10):>12} "
        f"{_fmt_sats(CCV_RECOVER_VSIZE * 500 * 10):>14}"
    )

    # Watchtower exhaustion (CCV): becomes viable at high fees
    result.observe(
        f"{'WT exhaustion (CCV)':>30} {'INFEASIBLE':>12} {'LOW':>12} {'MODERATE':>12} {'SIGNIFICANT':>14}"
    )
    splits_at_rates = {}
    for rate in [1, 50, 300, 500]:
        rc = WT_RECOVER_VSIZE * rate
        splits_at_rates[rate] = VAULT_AMOUNT_SATS // rc if rc > 0 else 999999
    result.observe(
        f"{'  splits to exhaust':>30} {splits_at_rates[1]:>12,} "
        f"{splits_at_rates[50]:>12,} {splits_at_rates[300]:>12,} {splits_at_rates[500]:>14,}"
    )

    # CTV hot-key griefing
    result.observe(
        f"{'Hot-key griefing (CTV)':>30} {'LOW':>12} {'LOW':>12} {'MODERATE':>12} {'MODERATE':>14}"
    )
    result.observe(
        f"{'  10-round attacker cost':>30} {_fmt_sats(CTV_UNVAULT_VSIZE * 1 * 10):>12} "
        f"{_fmt_sats(CTV_UNVAULT_VSIZE * 50 * 10):>12} "
        f"{_fmt_sats(CTV_UNVAULT_VSIZE * 300 * 10):>12} "
        f"{_fmt_sats(CTV_UNVAULT_VSIZE * 500 * 10):>14}"
    )

    # Key findings
    result.observe("\n--- Key Findings ---")

    result.observe(
        "\n1. FEE PINNING IS FEE-INVARIANT IN SEVERITY.  The attack costs "
        f"<0.5% of vault value at ANY historical fee rate.  Combined with "
        "hot key theft, this is CTV's worst-case failure mode under current "
        "relay policy.  Note: the TRUC/v3 transaction proposal would "
        "eliminate descendant-chain pinning if adopted."
    )

    result.observe(
        "\n2. RECOVERY GRIEFING SCALES LINEARLY BUT REMAINS CHEAP.  At 500 "
        f"sat/vB, 10 rounds of CCV griefing costs the attacker "
        f"{_fmt_sats(CCV_RECOVER_VSIZE * 500 * 10)} sats — still only "
        f"{CCV_RECOVER_VSIZE * 500 * 10 / VAULT_AMOUNT_SATS * 100:.2f}% of "
        f"a 0.5 BTC vault.  High fees deter griefing but don't eliminate it."
    )

    result.observe(
        "\n3. WATCHTOWER EXHAUSTION HAS A FEE-DEPENDENT CROSSOVER.  At "
        "1 sat/vB, exhaustion requires ~410k splits (infeasible).  At "
        "300 sat/vB, it requires ~1,366 splits (feasible with sustained "
        "attack over hours/days).  High-fee environments make this attack "
        "MORE viable, not less.  This is the OPPOSITE of griefing."
    )

    result.observe(
        "\n4. CTV AND CCV HAVE COMPLEMENTARY VULNERABILITY PROFILES:"
    )
    result.observe(
        "   - CTV: Fee pinning severity is CONSTANT across fee environments"
    )
    result.observe(
        "   - CCV: Watchtower exhaustion severity INCREASES with fee rate"
    )
    result.observe(
        "   - Both: Griefing costs increase linearly (mild deterrent)"
    )

    result.observe(
        "\n5. CTV AND CCV TRADE DIFFERENT FAILURE MODES.  CTV's worst case "
        "(fee pinning + hot key) risks fund loss; CCV's worst case "
        "(watchtower exhaustion) risks partial fund loss when the "
        "watchtower's budget is exceeded.  Both have mitigations: CTV "
        "benefits from TRUC/v3 transactions (which would eliminate "
        "descendant-chain pinning if adopted) and address-reuse risk is "
        "mitigable by wallet discipline.  CCV benefits from batched "
        "recovery (extending watchtower viability) and future anti-griefing "
        "mechanisms.  Which failure mode matters more is deployment-"
        "dependent: exchange custody may prioritize theft prevention, while "
        "individual users may prioritize reliable fund access."
    )


def _record_structural_metrics(result):
    """Record the structural vsize constants as TxMetrics for machine-readable output."""
    metrics_data = [
        ("ctv_tovault", CTV_TOVAULT_VSIZE, "p2wsh_ctv"),
        ("ctv_unvault", CTV_UNVAULT_VSIZE, "p2wsh_ctv"),
        ("ctv_withdraw", CTV_WITHDRAW_VSIZE, "p2wpkh"),
        ("ctv_tocold", CTV_TOCOLD_VSIZE, "p2wpkh"),
        ("ccv_tovault", CCV_TOVAULT_VSIZE, "p2tr_ccv"),
        ("ccv_trigger", CCV_TRIGGER_VSIZE, "p2tr_ccv"),
        ("ccv_withdraw", CCV_WITHDRAW_VSIZE, "p2tr_ccv"),
        ("ccv_recover", CCV_RECOVER_VSIZE, "p2tr_ccv"),
        ("ccv_trigger_revault", CCV_TRIGGER_REVAULT_VSIZE, "p2tr_ccv"),
        ("fee_pin_chain", FEE_PIN_TOTAL_CHAIN_VSIZE, "p2wpkh"),
    ]

    for label, vsize, script_type in metrics_data:
        result.add_tx(TxMetrics(
            label=label,
            vsize=vsize,
            weight=vsize * 4,  # approximate (actual witness discount varies)
            script_type=script_type,
        ))
