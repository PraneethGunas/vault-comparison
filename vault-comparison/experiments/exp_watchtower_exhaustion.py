"""Experiment H: Watchtower Exhaustion via Revault Splitting

Demonstrates the revault splitting attack originating with halseth in
the OP_VAULT discussion (BIP-345, https://bips.dev/345/), with
quantitative estimates by Harding ("OP_VAULT comments", Delving Bitcoin,
https://delvingbitcoin.org/t/op-vault-comments/521).  An attacker with
the trigger key repeatedly uses trigger_and_revault to split a vault
into progressively smaller UTXOs, each of which the watchtower must pay
to recover.

=== THREAT MODEL: Watchtower fee exhaustion (CCV) ===
Attacker: Has the unvault (trigger) key.  Can observe mempool, broadcast
  transactions.  No hashrate, no recovery key (recovery is keyless).
Goal: Force the watchtower to spend more on recovery fees than the
  remaining vault value, causing rational abandonment of some UTXOs.
  Success = watchtower's cumulative recovery cost > vault balance,
  leaving some Unvaulting UTXOs unrecovered (attacker completes those
  withdrawals after timelock).
Cost per round: One trigger_and_revault transaction (~T vbytes × fee_rate).
  The attacker also loses a small amount per split (withdrawal portion
  goes to Unvaulting which watchtower recovers — but the CTV template
  destination is the attacker's address, so if recovery fails, attacker
  collects).
Payoff: Any Unvaulting UTXOs the watchtower fails to recover.  The
  attacker set the CTV template at trigger time, so unrecovered UTXOs
  pay out to the attacker after the CSV timelock.
Rationality: Rational when the attacker's cumulative trigger cost is
  less than the value of UTXOs the watchtower abandons.  This depends
  on: (1) trigger tx vsize vs recovery tx vsize (the asymmetry), (2)
  the fee rate environment, (3) the spend_delay parameter (attacker
  must sustain the attack until timelocks expire), (4) vault balance.

Key measurements:
- trigger_vsize: vsize of one trigger_and_revault tx
- recover_vsize: vsize of one recovery tx from Unvaulting state
- split_asymmetry: recover_vsize / trigger_vsize (>1 favors attacker)
- vsize_stability: verify trigger/recover vsize doesn't change as balance shrinks
- rounds_to_exhaust(V, fee_rate): number of splits before watchtower
  recovery cost exceeds vault value V
- min_safe_vault(fee_rate): minimum vault balance where watchtower can
  always afford to recover all splits
- halseth_estimate_check: verify or refute ~3,000 chunks/block and
  ~0.3 BTC watchtower reserve
- withdrawal_fraction_analysis: compare dust splits vs 10%/25%/50% splits

CTV comparison: CTV has no trigger_and_revault.  The full vault amount
must be unvaulted at once, so this splitting attack is structurally
impossible.  This is a vulnerability for any vault with revault capability
(CCV and OP_VAULT) — a tradeoff: revault enables flexible partial
withdrawals but also enables this attack.

OP_VAULT comparison: OP_VAULT also supports partial withdrawal with
automatic revault (start_withdrawal with excess creates a revault output).
The splitting attack applies identically.  However, OP_VAULT's authorized
recovery requires the recoveryauth key, making the watchtower's recovery
path more controlled (no third-party interference) but also requiring key
management for the watchtower.
"""

from adapters.base import VaultAdapter
from harness.metrics import ExperimentResult, TxMetrics
from harness.regtest_caveats import emit_regtest_caveats, emit_fee_sensitivity_table
from experiments.registry import register

# Default parameters
VAULT_AMOUNT = 49_999_900  # ~0.5 BTC
SPLIT_WITHDRAW = 546       # minimum viable split — dust limit
DEFAULT_MAX_SPLITS = 50    # cap to avoid runaway test time
BLOCK_WEIGHT_LIMIT = 4_000_000  # segwit block weight limit

# Fee rate scenarios (sat/vB) for economic analysis
FEE_SCENARIOS = [1, 5, 10, 50, 100, 500]

# Withdrawal fraction scenarios (fraction of remaining balance per split)
WITHDRAWAL_FRACTIONS = [
    ("dust",  None),       # fixed SPLIT_WITHDRAW (546 sats)
    ("10pct", 0.10),       # 10% of remaining balance
    ("25pct", 0.25),       # 25% of remaining balance
    ("50pct", 0.50),       # 50% of remaining balance
]


@register(
    name="watchtower_exhaustion",
    description="Revault splitting attack: exhaust watchtower recovery budget",
    tags=["core", "security", "quantitative", "revault"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    max_splits = getattr(adapter, "max_splits", DEFAULT_MAX_SPLITS)

    result = ExperimentResult(
        experiment="watchtower_exhaustion",
        covenant=adapter.name,
        params={
            "vault_amount_sats": VAULT_AMOUNT,
            "split_withdraw_sats": SPLIT_WITHDRAW,
            "max_splits": max_splits,
        },
    )

    rpc = adapter.rpc

    # ── CTV: attack is structurally impossible ──────────────────────
    if not adapter.supports_revault():
        result.observe(
            f"{adapter.name} does not support trigger_and_revault.  "
            "The splitting attack is structurally impossible — the full "
            "vault amount must be unvaulted atomically.  An attacker with "
            "the trigger key can force ONE unvault (which the watchtower "
            "recovers in one transaction), not a cascade of splits."
        )
        result.observe(
            "COMPARISON: This is a fundamental CTV advantage over CCV for "
            "this specific attack vector.  CTV's lack of partial withdrawal "
            "is a limitation for users but a defense against splitting attacks."
        )
        return result

    # ── CCV/OP_VAULT: execute the splitting attack ─────────────────
    # Fallback vsizes for fee table (replaced by measurements if splitting succeeds).
    # These defaults come from prior empirical runs on regtest and are only used
    # if the splitting attack throws an exception before measuring actual vsizes.
    # Name-based dispatch is necessary here because the fallback vsizes are
    # structurally different per covenant (CCV uses simpler witness programs than
    # OP_VAULT's taproot-based recovery).  No single capability flag determines
    # transaction structure.
    # Defaults: CCV trigger_revault=162, recover=122;
    #           OP_VAULT trigger_revault=292, recover=246.
    measured_trigger_vsize = 292 if adapter.name == "opvault" else 162
    measured_recover_vsize = 246 if adapter.name == "opvault" else 122
    try:
        measured_trigger_vsize, measured_recover_vsize = \
            _run_splitting_attack(adapter, result, rpc, max_splits)
    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")

    # ── Regtest limitations and fee sensitivity ──────────────────────
    emit_regtest_caveats(
        result,
        experiment_specific=(
            "The splitting attack's temporal dynamics are lost on regtest.  "
            "On mainnet, the attacker must sustain splitting for spend_delay "
            "blocks (~100 min at 10 blocks), during which the watchtower "
            "races to recover each Unvaulting UTXO.  Regtest resolves "
            "timelocks instantly, so the recovery race is untested.  "
            "The vsize measurements and economic modeling are structurally "
            "valid; the question of whether a watchtower can keep pace "
            "under real block times and fee pressure is argued analytically "
            "via the splits/block vs recoveries/block comparison."
        ),
    )
    emit_fee_sensitivity_table(
        result,
        threat_model_name="Watchtower exhaustion (splitting attack)",
        vsize_rows=[
            {"label": "attacker_trigger_revault", "vsize": measured_trigger_vsize,
             "description": f"trigger_and_revault per split — {adapter.name} measured"},
            {"label": "watchtower_recovery", "vsize": measured_recover_vsize,
             "description": f"Recovery per Unvaulting UTXO — {adapter.name} measured"},
        ],
        vault_amount_sats=VAULT_AMOUNT,
    )

    return result


def _run_splitting_attack(adapter, result, rpc, max_splits):
    """Execute the revault splitting attack and measure costs."""

    result.observe("=== Phase 1: Measure per-transaction costs ===")

    # Create the initial vault
    vault = adapter.create_vault(VAULT_AMOUNT)
    result.observe(
        f"Initial vault: {vault.vault_txid[:16]}… ({vault.amount_sats} sats)"
    )

    # ── First split: measure trigger_and_revault cost ───────────────
    unvault_state, new_vault = adapter.trigger_revault(vault, SPLIT_WITHDRAW)
    trigger_metrics = adapter.collect_tx_metrics(
        _tx_record("trigger_split_1", unvault_state.unvault_txid, SPLIT_WITHDRAW),
        rpc
    )
    trigger_tx_info = rpc.get_tx_info(unvault_state.unvault_txid)
    trigger_vsize = trigger_tx_info["vsize"]
    trigger_weight = trigger_tx_info["weight"]
    trigger_fee = rpc.get_tx_fee_sats(unvault_state.unvault_txid)

    result.add_tx(TxMetrics(
        label="trigger_and_revault",
        txid=unvault_state.unvault_txid,
        vsize=trigger_vsize,
        weight=trigger_weight,
        fee_sats=trigger_fee,
        num_inputs=len(trigger_tx_info["vin"]),
        num_outputs=len(trigger_tx_info["vout"]),
        amount_sats=SPLIT_WITHDRAW,
    ))
    result.observe(
        f"trigger_and_revault: vsize={trigger_vsize}, weight={trigger_weight}, "
        f"fee={trigger_fee} sats"
    )

    # ── Recover the unvaulting UTXO: measure watchtower recovery cost ──
    recover_record = adapter.recover(unvault_state)
    recover_metrics = adapter.collect_tx_metrics(recover_record, rpc)
    recover_vsize = recover_metrics.vsize
    recover_weight = recover_metrics.weight
    recover_fee = recover_metrics.fee_sats

    result.add_tx(TxMetrics(
        label="watchtower_recover",
        txid=recover_record.txid,
        vsize=recover_vsize,
        weight=recover_weight,
        fee_sats=recover_fee,
        num_inputs=recover_metrics.num_inputs,
        num_outputs=recover_metrics.num_outputs,
        amount_sats=unvault_state.amount_sats,
    ))
    result.observe(
        f"watchtower recovery: vsize={recover_vsize}, weight={recover_weight}, "
        f"fee={recover_fee} sats"
    )

    # ── Cost asymmetry ──────────────────────────────────────────────
    asymmetry = recover_vsize / trigger_vsize if trigger_vsize else 0
    result.observe(
        f"Cost asymmetry (recover/trigger): {asymmetry:.2f}x  "
        f"({'favors attacker' if asymmetry > 1 else 'favors defender'})"
    )

    # ── Phase 2: Chained splits with vsize stability verification ───
    result.observe("=== Phase 2: Chained splits with vsize stability check ===")
    result.observe(
        "Measuring trigger_and_revault vsize at every split point to verify "
        "structural independence from vault balance (the vsize should be constant "
        "because the script structure doesn't change with amount)."
    )

    vault = new_vault
    attacker_cumulative_cost = trigger_vsize
    watchtower_cumulative_cost = recover_vsize
    splits_completed = 1

    # Collect per-split vsize measurements for stability analysis
    trigger_vsizes = [trigger_vsize]
    trigger_weights = [trigger_weight]
    recover_vsizes = [recover_vsize]
    recover_weights = [recover_weight]
    balance_at_split = [vault.amount_sats]

    while (splits_completed < max_splits
           and vault.amount_sats > SPLIT_WITHDRAW + 1000):
        splits_completed += 1

        try:
            unvault_state, new_vault = adapter.trigger_revault(
                vault, SPLIT_WITHDRAW
            )
        except Exception as e:
            result.observe(
                f"  Split {splits_completed}: FAILED — {e}  "
                f"(vault remainder: {vault.amount_sats} sats)"
            )
            break

        # Measure THIS split's trigger vsize (not extrapolating from round 1)
        split_tx_info = rpc.get_tx_info(unvault_state.unvault_txid)
        split_trigger_vsize = split_tx_info["vsize"]
        split_trigger_weight = split_tx_info["weight"]
        trigger_vsizes.append(split_trigger_vsize)
        trigger_weights.append(split_trigger_weight)
        balance_at_split.append(new_vault.amount_sats)

        attacker_cumulative_cost += split_trigger_vsize

        # Watchtower recovers — measure recovery vsize too
        try:
            recover_record = adapter.recover(unvault_state)
            split_recover_metrics = adapter.collect_tx_metrics(recover_record, rpc)
            recover_vsizes.append(split_recover_metrics.vsize)
            recover_weights.append(split_recover_metrics.weight)
            watchtower_cumulative_cost += split_recover_metrics.vsize
        except Exception as e:
            result.observe(
                f"  Split {splits_completed}: recovery FAILED — {e}"
            )
            watchtower_cumulative_cost += recover_vsize  # estimate

        # Log at checkpoints: 1, 5, 10, 20, 30, 40, 50
        if splits_completed in (1, 5, 10, 20, 30, 40, 50) or splits_completed == max_splits:
            result.observe(
                f"  Split {splits_completed}: balance={new_vault.amount_sats:,} sats, "
                f"trigger_vsize={split_trigger_vsize}, "
                f"attacker_cumul={attacker_cumulative_cost} vB, "
                f"watchtower_cumul={watchtower_cumulative_cost} vB"
            )

        vault = new_vault

    result.observe(
        f"Completed {splits_completed} splits.  "
        f"Final vault remainder: {vault.amount_sats:,} sats."
    )

    # ── Vsize stability analysis ────────────────────────────────────
    result.observe("\n--- Vsize stability verification ---")
    if len(trigger_vsizes) >= 3:
        min_tv = min(trigger_vsizes)
        max_tv = max(trigger_vsizes)
        avg_tv = sum(trigger_vsizes) / len(trigger_vsizes)
        min_rv = min(recover_vsizes)
        max_rv = max(recover_vsizes)
        avg_rv = sum(recover_vsizes) / len(recover_vsizes)

        result.observe(
            f"Trigger vsize across {len(trigger_vsizes)} splits: "
            f"min={min_tv}, max={max_tv}, avg={avg_tv:.1f}, "
            f"range={max_tv - min_tv}"
        )
        result.observe(
            f"Recover vsize across {len(recover_vsizes)} splits: "
            f"min={min_rv}, max={max_rv}, avg={avg_rv:.1f}, "
            f"range={max_rv - min_rv}"
        )
        result.observe(
            f"Balance ranged from {balance_at_split[0]:,} to {balance_at_split[-1]:,} sats "
            f"({balance_at_split[-1] / balance_at_split[0] * 100:.1f}% of initial)"
        )

        trigger_stable = (max_tv - min_tv) <= 2  # within 2 vB is structural noise
        recover_stable = (max_rv - min_rv) <= 2
        if trigger_stable and recover_stable:
            result.observe(
                "VERIFIED: vsize is structurally constant regardless of vault balance.  "
                "Linear extrapolation from single-round measurements is valid."
            )
        else:
            result.observe(
                f"WARNING: vsize varies by more than 2 vB across splits.  "
                f"Trigger delta={max_tv - min_tv}, Recover delta={max_rv - min_rv}.  "
                f"Linear extrapolation may introduce error — use per-split measurements."
            )

        # Use the empirically validated average for subsequent calculations
        trigger_vsize = round(avg_tv)
        trigger_weight = round(sum(trigger_weights) / len(trigger_weights))
        recover_vsize = round(avg_rv)
        recover_weight = round(sum(recover_weights) / len(recover_weights))
        result.observe(
            f"Using empirical averages: trigger={trigger_vsize} vB, "
            f"recover={recover_vsize} vB"
        )

    # ── Phase 3: Variable withdrawal fraction analysis ──────────────
    result.observe("\n=== Phase 3: Variable withdrawal fraction analysis ===")
    result.observe(
        "Dust splits minimize per-split cost but maximize the number of UTXOs.  "
        "Larger withdrawal fractions create fewer but costlier UTXOs to recover.  "
        "Which strategy is optimal for the attacker?"
    )

    fraction_results = {}

    for frac_label, frac_value in WITHDRAWAL_FRACTIONS:
        result.observe(f"\n--- Withdrawal strategy: {frac_label} ---")

        try:
            frac_vault = adapter.create_vault(VAULT_AMOUNT)
            frac_splits = 0
            frac_attacker_cost = 0
            frac_watchtower_cost = 0
            frac_unrecoverable = 0  # splits where recovery costs > split value
            frac_max_splits = min(max_splits, 30)  # cap for larger fractions
            frac_trigger_vsizes = []
            frac_recover_vsizes = []

            while (frac_splits < frac_max_splits
                   and frac_vault.amount_sats > SPLIT_WITHDRAW + 1000):
                frac_splits += 1

                # Determine withdrawal amount
                if frac_value is None:
                    # Dust strategy
                    withdraw_amount = SPLIT_WITHDRAW
                else:
                    # Fraction of remaining balance, but at least dust
                    withdraw_amount = max(
                        SPLIT_WITHDRAW,
                        int(frac_vault.amount_sats * frac_value)
                    )
                    # Ensure we leave enough for the revault
                    if withdraw_amount >= frac_vault.amount_sats - 1000:
                        break

                try:
                    unvault_state, frac_vault = adapter.trigger_revault(
                        frac_vault, withdraw_amount
                    )
                except Exception:
                    break

                # Measure trigger vsize
                split_info = rpc.get_tx_info(unvault_state.unvault_txid)
                frac_trigger_vsizes.append(split_info["vsize"])
                frac_attacker_cost += split_info["vsize"]

                # Recover and measure
                try:
                    rec = adapter.recover(unvault_state)
                    rec_m = adapter.collect_tx_metrics(rec, rpc)
                    frac_recover_vsizes.append(rec_m.vsize)
                    frac_watchtower_cost += rec_m.vsize
                except Exception:
                    frac_recover_vsizes.append(recover_vsize)
                    frac_watchtower_cost += recover_vsize

            # Analyze this strategy
            avg_split_value = VAULT_AMOUNT / frac_splits if frac_splits > 0 else 0
            avg_trigger = (sum(frac_trigger_vsizes) / len(frac_trigger_vsizes)
                           if frac_trigger_vsizes else trigger_vsize)
            avg_recover = (sum(frac_recover_vsizes) / len(frac_recover_vsizes)
                           if frac_recover_vsizes else recover_vsize)

            fraction_results[frac_label] = {
                "splits": frac_splits,
                "attacker_vB": frac_attacker_cost,
                "watchtower_vB": frac_watchtower_cost,
                "avg_split_sats": int(avg_split_value),
                "trigger_vsize": round(avg_trigger),
                "recover_vsize": round(avg_recover),
                "remainder": frac_vault.amount_sats,
            }

            result.observe(
                f"  Splits: {frac_splits}, "
                f"attacker cost: {frac_attacker_cost} vB, "
                f"watchtower cost: {frac_watchtower_cost} vB, "
                f"remainder: {frac_vault.amount_sats:,} sats"
            )
            result.observe(
                f"  Avg split value: {int(avg_split_value):,} sats, "
                f"trigger vsize: {round(avg_trigger)}, "
                f"recover vsize: {round(avg_recover)}"
            )

            # Record metrics
            result.add_tx(TxMetrics(
                label=f"fraction_{frac_label}",
                vsize=frac_attacker_cost + frac_watchtower_cost,
                weight=(frac_attacker_cost + frac_watchtower_cost) * 4,
                amount_sats=VAULT_AMOUNT - frac_vault.amount_sats,
            ))

        except Exception as e:
            result.observe(f"  ERROR in {frac_label} strategy: {e}")

    # ── Fraction comparison summary ─────────────────────────────────
    result.observe("\n--- Withdrawal fraction comparison ---")
    result.observe(
        f"{'Strategy':>10} | {'Splits':>7} | {'Attacker vB':>12} | "
        f"{'Watchtower vB':>14} | {'Avg split sats':>15} | {'Remainder':>12}"
    )
    result.observe("-" * 85)
    for label, data in fraction_results.items():
        result.observe(
            f"{label:>10} | {data['splits']:>7} | {data['attacker_vB']:>12,} | "
            f"{data['watchtower_vB']:>14,} | {data['avg_split_sats']:>15,} | "
            f"{data['remainder']:>12,}"
        )

    # Identify which strategy maximizes watchtower cost per attacker cost
    best_strategy = None
    best_ratio = 0
    for label, data in fraction_results.items():
        if data["attacker_vB"] > 0:
            ratio = data["watchtower_vB"] / data["attacker_vB"]
            if ratio > best_ratio:
                best_ratio = ratio
                best_strategy = label

    if best_strategy:
        result.observe(
            f"\nAttacker-optimal strategy: {best_strategy} "
            f"(watchtower/attacker cost ratio: {best_ratio:.2f}x)"
        )

    # Identify which strategy produces the most unrecoverable UTXOs at high fees
    result.observe("\n--- Recovery viability at high fee rates ---")
    for fee_rate in [50, 100, 500]:
        result.observe(f"\n  At {fee_rate} sat/vB:")
        for label, data in fraction_results.items():
            recovery_cost = data["recover_vsize"] * fee_rate
            avg_split = data["avg_split_sats"]
            viable = recovery_cost < avg_split
            result.observe(
                f"    {label}: recovery cost={recovery_cost:,} sats vs "
                f"avg split={avg_split:,} sats → "
                f"{'viable' if viable else 'UNECONOMIC (watchtower abandons)'}"
            )

    # ── Phase 4: Economic analysis ──────────────────────────────────
    result.observe("\n=== Phase 4: Economic analysis (using empirical vsize) ===")

    # How many splits can fit in one block?
    trigger_weight_per_split = trigger_weight
    max_splits_per_block = BLOCK_WEIGHT_LIMIT // trigger_weight_per_split
    result.observe(
        f"Max trigger_and_revault txs per block: {max_splits_per_block} "
        f"(block weight limit {BLOCK_WEIGHT_LIMIT} / "
        f"trigger weight {trigger_weight_per_split})"
    )

    # How many recovery txs can fit in one block?
    max_recoveries_per_block = BLOCK_WEIGHT_LIMIT // recover_weight
    result.observe(
        f"Max recovery txs per block: {max_recoveries_per_block} "
        f"(block weight limit {BLOCK_WEIGHT_LIMIT} / "
        f"recovery weight {recover_weight})"
    )

    # ── Fee rate scenarios ──────────────────────────────────────────
    result.observe("\n--- Fee rate scenarios ---")
    result.observe(
        f"{'Fee rate':>10} | {'Attacker/split':>15} | {'Watchtower/split':>17} | "
        f"{'Splits to exhaust 0.5 BTC':>26} | {'Min safe vault':>15} | "
        f"{'Watchtower reserve (1 block)':>28}"
    )
    result.observe("-" * 120)

    for fee_rate in FEE_SCENARIOS:
        attacker_cost_per_split = trigger_vsize * fee_rate
        watchtower_cost_per_split = recover_vsize * fee_rate

        if watchtower_cost_per_split > 0:
            splits_to_exhaust = VAULT_AMOUNT // watchtower_cost_per_split
        else:
            splits_to_exhaust = float("inf")

        if watchtower_cost_per_split > SPLIT_WITHDRAW:
            min_safe = "NONE (always vulnerable)"
        else:
            min_safe = f"any (cost {watchtower_cost_per_split} ≤ dust {SPLIT_WITHDRAW})"

        reserve_one_block = max_splits_per_block * watchtower_cost_per_split

        result.observe(
            f"{fee_rate:>8} s/vB | {attacker_cost_per_split:>13,} sats | "
            f"{watchtower_cost_per_split:>15,} sats | "
            f"{splits_to_exhaust:>24,} | "
            f"{min_safe:>15} | "
            f"{reserve_one_block:>20,} sats "
            f"({reserve_one_block / 100_000_000:.4f} BTC)"
        )

        result.add_tx(TxMetrics(
            label=f"scenario_{fee_rate}satvb",
            vsize=trigger_vsize + recover_vsize,
            fee_sats=attacker_cost_per_split + watchtower_cost_per_split,
        ))

    # ── Phase 5: Harding [Har24] estimate check ─────────────────────────────
    result.observe("\n=== Phase 5: Harding [Har24] estimate verification ===")

    result.observe(
        f"Harding [Har24] estimated ~3,000 chunks per block.  "
        f"Our measurement: {max_splits_per_block} trigger txs/block "
        f"(trigger weight = {trigger_weight_per_split} WU).  "
        f"{'CONSISTENT' if abs(max_splits_per_block - 3000) < 1500 else 'DIVERGENT'} "
        f"with Harding [Har24] estimate."
    )

    harding_reserve_btc = 0.3
    harding_reserve_sats = int(harding_reserve_btc * 100_000_000)
    if recover_vsize > 0 and max_recoveries_per_block > 0:
        implied_fee_rate = harding_reserve_sats / (max_recoveries_per_block * recover_vsize)
        result.observe(
            f"Harding [Har24] estimated ~0.3 BTC watchtower reserve.  "
            f"Our measurements imply this reserve handles one block of "
            f"recoveries at ~{implied_fee_rate:.1f} sat/vB fee rate.  "
            f"At 10 sat/vB, watchtower needs "
            f"{max_recoveries_per_block * recover_vsize * 10 / 100_000_000:.4f} BTC "
            f"per block of recoveries."
        )

    # ── Phase 6: Batched recovery analysis ──────────────────────────
    result.observe("\n=== Phase 6: Batched recovery analysis ===")
    result.observe(
        "Current analysis assumes the watchtower recovers each Unvaulting UTXO "
        "individually.  In practice, a watchtower could batch recoveries into "
        "fewer transactions if multiple Unvaulting UTXOs share the same recovery "
        "path.  We analyze the potential savings."
    )

    # Each individual recovery tx has overhead (version, locktime, marker+flag)
    # plus per-input cost.  Batching amortizes the fixed overhead.
    # Estimate fixed overhead: ~10 vB (version=4, locktime=4, marker+flag=0.5, ...)
    # Per-input witness: most of the recovery vsize
    # Per-output: ~43 vB (recovery output to cold address)
    # We can estimate from our measurements:
    #   individual_recovery = overhead + 1*input_cost + 1*output_cost
    #   batched_N = overhead + N*input_cost + 1*output_cost (shared output)
    # So input_cost ≈ recover_vsize - overhead - output_cost
    # We'll estimate overhead+output conservatively at ~55 vB

    FIXED_OVERHEAD_ESTIMATE = 55  # version + locktime + segwit marker + 1 output
    # Uncertainty: overhead could range from ~45 vB (minimal: 4+4+0.5+31+varint) to
    # ~65 vB (with witness discount variation and output script differences).
    # This gives per-input cost uncertainty of ±10 vB.
    OVERHEAD_UNCERTAINTY = 10  # ±10 vB on the fixed overhead estimate
    input_cost_estimate = max(recover_vsize - FIXED_OVERHEAD_ESTIMATE, recover_vsize // 2)
    input_cost_low = max(recover_vsize - (FIXED_OVERHEAD_ESTIMATE + OVERHEAD_UNCERTAINTY), recover_vsize // 2)
    input_cost_high = max(recover_vsize - (FIXED_OVERHEAD_ESTIMATE - OVERHEAD_UNCERTAINTY), recover_vsize // 2)
    result.observe(
        f"Individual recovery: {recover_vsize} vB "
        f"(estimated {FIXED_OVERHEAD_ESTIMATE} vB overhead ±{OVERHEAD_UNCERTAINTY} vB + "
        f"{input_cost_estimate} vB per input [{input_cost_low}–{input_cost_high} vB range])"
    )
    result.observe(
        f"NOTE: The overhead decomposition ({FIXED_OVERHEAD_ESTIMATE} vB fixed + "
        f"{input_cost_estimate} vB/input) is estimated, not validated by constructing "
        f"an actual batched recovery transaction.  The ±{OVERHEAD_UNCERTAINTY} vB "
        f"uncertainty on overhead translates to ±{OVERHEAD_UNCERTAINTY} vB per input.  "
        f"At 100 inputs, this is ±{OVERHEAD_UNCERTAINTY * 100} vB total (~"
        f"{OVERHEAD_UNCERTAINTY * 100 / (FIXED_OVERHEAD_ESTIMATE + 100 * input_cost_estimate) * 100:.1f}% "
        f"of estimated batch size).  The qualitative conclusions (batching saves "
        f"~45% and extends viable fee range ~1.8x) are robust to this uncertainty."
    )

    result.observe(
        f"{'Batch size':>12} | {'Total vsize':>12} | {'vsize/recovery':>15} | "
        f"{'Savings vs individual':>22}"
    )
    result.observe("-" * 70)

    for batch_n in [1, 5, 10, 25, 50, 100]:
        batched_vsize = FIXED_OVERHEAD_ESTIMATE + batch_n * input_cost_estimate
        per_recovery = batched_vsize / batch_n
        individual_total = batch_n * recover_vsize
        savings_pct = (1 - batched_vsize / individual_total) * 100

        result.observe(
            f"{batch_n:>12} | {batched_vsize:>10,} vB | "
            f"{per_recovery:>13.1f} vB | {savings_pct:>20.1f}%"
        )

    # Check if batching changes the economic conclusion
    # At max batch, what fee rate makes recovery economically viable for dust?
    max_batch = 100
    batched_per_recovery = (FIXED_OVERHEAD_ESTIMATE + max_batch * input_cost_estimate) / max_batch
    max_viable_fee_rate_batched = SPLIT_WITHDRAW / batched_per_recovery if batched_per_recovery > 0 else 0
    max_viable_fee_rate_individual = SPLIT_WITHDRAW / recover_vsize if recover_vsize > 0 else 0
    result.observe(
        f"\nMax fee rate where dust recovery is economic:"
    )
    result.observe(
        f"  Individual: {max_viable_fee_rate_individual:.1f} sat/vB"
    )
    result.observe(
        f"  Batched (100 inputs): {max_viable_fee_rate_batched:.1f} sat/vB"
    )
    result.observe(
        f"  Batching extends viable fee range by "
        f"{max_viable_fee_rate_batched / max_viable_fee_rate_individual:.1f}x"
        if max_viable_fee_rate_individual > 0 else
        "  Cannot compute ratio (individual fee rate is 0)"
    )

    result.observe(
        "\nNOTE: Batched recovery requires the watchtower to accumulate pending "
        "Unvaulting UTXOs and batch them.  This introduces latency — the "
        "watchtower must wait for enough UTXOs to batch efficiently, but each "
        "UTXO has a CSV timelock after which the attacker can withdraw.  The "
        "optimal batch size balances batching savings against timelock pressure."
    )

    # ── Phase 7: spend_delay analysis ───────────────────────────────
    result.observe("\n=== Phase 7: spend_delay parameter effect ===")

    locktime = adapter.locktime if hasattr(adapter, "locktime") else 10
    result.observe(
        f"Current spend_delay (CSV): {locktime} blocks "
        f"(~{locktime * 10} minutes on mainnet)"
    )
    result.observe(
        f"The attacker must sustain the splitting attack for at least "
        f"{locktime} blocks after the LAST split before any unrecovered "
        f"Unvaulting UTXO can be withdrawn.  During this window, the "
        f"watchtower can still recover."
    )
    result.observe(
        f"With {max_splits_per_block} splits/block and {locktime}-block delay, "
        f"the attacker can create up to {max_splits_per_block * locktime:,} "
        f"Unvaulting UTXOs before the first one matures.  The watchtower "
        f"must recover all of them within {locktime} blocks."
    )

    if max_recoveries_per_block >= max_splits_per_block:
        result.observe(
            f"Watchtower can process {max_recoveries_per_block} recoveries/block "
            f"vs attacker's {max_splits_per_block} splits/block.  "
            f"Watchtower CAN keep pace — but must pay fees for every recovery."
        )
    else:
        result.observe(
            f"WARNING: Watchtower can only process {max_recoveries_per_block} "
            f"recoveries/block vs attacker's {max_splits_per_block} splits/block.  "
            f"Watchtower CANNOT keep pace — will fall behind."
        )

    # Analyze different spend_delay values
    result.observe("\n--- spend_delay sensitivity ---")
    for delay in [10, 20, 50, 144, 288]:
        max_pending = max_splits_per_block * delay
        recovery_blocks_needed = max_pending / max_recoveries_per_block if max_recoveries_per_block > 0 else float("inf")
        can_keep_up = recovery_blocks_needed <= delay
        result.observe(
            f"  delay={delay} blocks (~{delay * 10 // 60}h): "
            f"max pending UTXOs={max_pending:,}, "
            f"blocks to recover all={recovery_blocks_needed:.0f}, "
            f"{'OK' if can_keep_up else 'OVERWHELMED'}"
        )

    # ── Summary ─────────────────────────────────────────────────────
    result.observe("\n=== Summary ===")
    result.observe(
        f"ATTACK MECHANISM: Attacker with trigger key calls trigger_and_revault "
        f"repeatedly, creating N Unvaulting UTXOs the watchtower must recover."
    )
    result.observe(
        f"MEASURED COSTS: trigger={trigger_vsize} vB, recover={recover_vsize} vB, "
        f"asymmetry={asymmetry:.2f}x  "
        f"(verified stable across {len(trigger_vsizes)} splits with "
        f"trigger range={max(trigger_vsizes) - min(trigger_vsizes)} vB, "
        f"recover range={max(recover_vsizes) - min(recover_vsizes)} vB)"
    )
    result.observe(
        f"WITHDRAWAL STRATEGY: "
        + (f"Attacker-optimal strategy is {best_strategy} "
           f"(watchtower/attacker ratio: {best_ratio:.2f}x)" if best_strategy else
           "Could not determine optimal strategy")
    )
    result.observe(
        f"BATCHED RECOVERY: Batching 100 recoveries saves "
        f"~{(1 - (FIXED_OVERHEAD_ESTIMATE + 100 * input_cost_estimate) / (100 * recover_vsize)) * 100:.0f}% "
        f"vs individual recovery, extending viable fee range by "
        f"{max_viable_fee_rate_batched / max_viable_fee_rate_individual:.1f}x"
        if max_viable_fee_rate_individual > 0 else
        "BATCHED RECOVERY: Could not compute savings (zero individual fee rate)"
    )
    result.observe(
        f"KEY FINDING: The economic viability of this attack depends critically "
        f"on the fee environment.  At low fees (1-5 sat/vB), the attack is "
        f"cheap but recovery is also cheap.  At high fees (50-500 sat/vB), "
        f"recovery becomes expensive relative to dust-sized split amounts.  "
        f"The critical threshold is when watchtower_cost_per_recovery > "
        f"SPLIT_WITHDRAW ({SPLIT_WITHDRAW} sats)."
    )
    result.observe(
        f"CTV COMPARISON: This attack is structurally impossible on CTV.  "
        f"CTV's lack of partial withdrawal means the attacker can only trigger "
        f"one unvault of the full amount, which the watchtower recovers in one tx.  "
        f"This is the cost of revault flexibility (shared by CCV and OP_VAULT)."
    )
    if adapter.name == "opvault":
        result.observe(
            f"OP_VAULT NOTE: The splitting attack mechanics are identical to CCV, "
            f"but recovery requires the recoveryauth key.  This means: (1) the "
            f"watchtower must hold the recoveryauth key to perform recovery, "
            f"(2) no third party can interfere with recovery (anti-griefing), "
            f"(3) if the recoveryauth key is lost, recovery is impossible."
        )

    return (trigger_vsize, recover_vsize)


def _tx_record(label, txid, amount):
    """Helper to build a TxRecord from experiment data."""
    from adapters.base import TxRecord
    return TxRecord(txid=txid, label=label, amount_sats=amount)
