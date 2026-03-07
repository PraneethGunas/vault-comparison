"""Experiment F: Forced-Recovery Griefing

Demonstrates the asymmetric cost of forced-recovery griefing attacks
on covenant vaults.  The critique of previous analysis: the claim that
"attacker cost ≈ defender cost per round" ignores the asymmetry.

=== RELATED WORK ===
Keyless recovery griefing is identified by Ingala in MATT/CCV design
discussions (bitcoin-dev mailing list, https://bips.dev/443/) as an
inherent property of CCV's permissionless recovery.  The vault custody
threat model follows Swambo et al. (https://arxiv.org/abs/2005.11776).
This experiment measures the vsize asymmetry between trigger and
recovery transactions, simulates a 10-round griefing loop, and
compares the CCV griefing surface with the CTV hot-key sweep analog.

=== THE ASYMMETRY ===
The attacker monitors the mempool for unvault transactions and front-runs
them with a recovery transaction (which requires no key material on CCV).
The defender must then RE-TRIGGER the unvault (paying trigger fees again),
and the attacker can immediately front-run again.

Per-round costs:
  - Attacker: one recovery tx (~R vbytes)
  - Defender: one trigger tx (~T vbytes) + opportunity cost of delayed withdrawal

Over N rounds:
  - Attacker cumulative: N × R × fee_rate
  - Defender cumulative: N × T × fee_rate  (trigger fees, NOT counting original)
  - Defender also loses: opportunity cost × N × expected_delay

The defender's per-round cost is HIGHER because T > R (triggers are larger
than recoveries) AND the defender bears opportunity cost.

=== THREAT MODEL: Forced-recovery griefing (CCV) ===
Attacker: NO key material required.  Any entity with a Bitcoin node that
  can observe the mempool and broadcast transactions.  Minimum viable
  attacker.
Goal: Deny vault liveness — prevent the vault owner from completing any
  withdrawal.  Success = defender abandons the withdrawal or exhausts
  patience/budget.
Attack cost: One recovery tx per round (~R vbytes × fee_rate).
  Front-running advantage: attacker sees unvault in mempool, broadcasts
  recovery with higher fee BEFORE unvault confirms.  If recovery fee >
  unvault fee, miners prefer the recovery tx.
Payoff: Zero direct financial gain.  Pure denial of service.
Rationality: Only rational with external incentive (competitor,
  extortionist, state actor).  But the cost is LOW — sustained griefing
  for 10 rounds at 10 sat/vB costs only ~18,000 sats.
Defender response: Re-trigger with higher fees each round (escalating
  cost).  Wait for low-fee periods.  Use out-of-band miner submission.
  Increase spend_delay to widen the recovery window.
Residual: No direct fund loss — attack is liveness-only.  Maximum
  damage = indefinite withdrawal delay + cumulative re-trigger fees.
  Operational severity depends on deployment context.

CTV comparison: CTV's tocold sweep is also vulnerable to front-running
  in the reverse direction — but the tocold is a CTV-committed transaction
  that the defender doesn't need to re-trigger.  The griefing surface is
  different: on CTV, the attacker with the hot key can grief by repeatedly
  triggering unvault (defender must repeatedly sweep to cold).  On CCV,
  anyone can grief by calling recover on any unvault.

=== EMPIRICAL DEMONSTRATION ===
Phase 1: Measure trigger and recovery vsize independently.  Compute the
  cost asymmetry ratio (trigger_vsize / recovery_vsize).
Phase 2: Simulate N rounds of the griefing loop:
  - Defender triggers unvault
  - Attacker calls recover (front-run)
  - Repeat
  Measure cumulative costs for both parties.
Phase 3: Fee-rate sensitivity — compute breakeven and exhaustion
  thresholds across fee environments.
Phase 4: spend_delay analysis — how spend_delay affects the attacker's
  timing window and the defender's re-trigger strategy.
Phase 5 (CTV): Demonstrate the CTV analog — hot-key griefing where the
  attacker repeatedly triggers unvault, forcing the defender to sweep to
  cold each time.
"""

from adapters.base import VaultAdapter, UnvaultState, TxRecord
from harness.metrics import ExperimentResult, TxMetrics
from harness.regtest_caveats import emit_regtest_caveats, emit_fee_sensitivity_table
from experiments.registry import register


VAULT_AMOUNT = 49_999_900
MAX_GRIEF_ROUNDS = 10  # default rounds of griefing to simulate


@register(
    name="recovery_griefing",
    description="Forced-recovery griefing: asymmetric cost analysis",
    tags=["core", "comparative", "security", "quantitative"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    result = ExperimentResult(
        experiment="recovery_griefing",
        covenant=adapter.name,
        params={"vault_amount_sats": VAULT_AMOUNT},
    )

    rpc = adapter.rpc

    try:
        if adapter.name == "ctv":
            _run_ctv_griefing(adapter, result, rpc)
        else:
            # CCV, OP_VAULT, and CAT+CSFS share the same griefing structure
            _run_trigger_recover_griefing(adapter, result, rpc)
    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")
        import traceback
        result.observe(traceback.format_exc())

    # ── Regtest limitations and fee sensitivity ──────────────────────
    emit_regtest_caveats(
        result,
        experiment_specific=(
            "The griefing attack's critical dynamic — mempool front-running — "
            "cannot be demonstrated on regtest.  On mainnet, the attacker "
            "monitors the mempool for unvault transactions and races to "
            "broadcast recovery before the unvault confirms.  Regtest mines "
            "instantly, so the 'race' is trivially won.  The vsize asymmetry "
            "(trigger vs recovery) is structurally valid; the front-running "
            "advantage is argued analytically, not demonstrated empirically."
        ),
    )
    emit_fee_sensitivity_table(
        result,
        threat_model_name="Forced-recovery griefing",
        vsize_rows=[
            {"label": "defender_trigger", "vsize": 154,
             "description": "Trigger unvault tx (defender pays)"},
            {"label": "attacker_recovery", "vsize": 122,
             "description": "Recovery tx (attacker front-runs)"},
        ],
        vault_amount_sats=VAULT_AMOUNT,
    )

    return result


def _run_ccv_griefing(adapter, result, rpc):
    """CCV: Anyone can call recover — no key material needed."""

    # ── Phase 1: Measure baseline costs ──────────────────────────────
    result.observe("=== Phase 1: Measure trigger and recovery vsize ===")

    vault = adapter.create_vault(VAULT_AMOUNT)
    result.observe(f"Vault created: {vault.vault_txid[:16]}... ({vault.amount_sats} sats)")

    # Trigger unvault and measure its cost
    unvault = adapter.trigger_unvault(vault)
    trigger_metrics = adapter.collect_tx_metrics(
        TxRecord(
            txid=unvault.unvault_txid,
            label="trigger",
            amount_sats=unvault.amount_sats,
        ),
        rpc,
    )
    trigger_vsize = trigger_metrics.vsize or 0
    result.observe(f"Trigger tx: {unvault.unvault_txid[:16]}... ({trigger_vsize} vB)")
    result.add_tx(trigger_metrics)

    # Recover (attacker's move) and measure its cost
    recover_record = adapter.recover(unvault)
    recover_metrics = adapter.collect_tx_metrics(recover_record, rpc)
    recover_vsize = recover_metrics.vsize or 0
    result.observe(f"Recovery tx: {recover_record.txid[:16]}... ({recover_vsize} vB)")
    result.add_tx(recover_metrics)

    # Cost asymmetry
    if recover_vsize > 0:
        asymmetry = trigger_vsize / recover_vsize
        result.observe(
            f"Cost asymmetry: trigger/recovery = {trigger_vsize}/{recover_vsize} "
            f"= {asymmetry:.2f}x"
        )
        result.observe(
            f"  The DEFENDER pays {asymmetry:.2f}x more per round than the "
            f"attacker (trigger is larger than recovery)."
        )
    else:
        asymmetry = 1.0
        result.observe("WARNING: Could not measure recovery vsize — using 1.0x asymmetry")

    # ── Phase 2: Simulate griefing loop ──────────────────────────────
    result.observe(f"=== Phase 2: Griefing loop ({MAX_GRIEF_ROUNDS} rounds) ===")

    attacker_cumulative_vsize = 0
    defender_cumulative_vsize = 0
    rounds_completed = 0

    for round_num in range(1, MAX_GRIEF_ROUNDS + 1):
        try:
            # Defender creates a fresh vault and triggers unvault
            vault = adapter.create_vault(VAULT_AMOUNT)
            unvault = adapter.trigger_unvault(vault)

            # Measure trigger cost
            t_metrics = adapter.collect_tx_metrics(
                TxRecord(
                    txid=unvault.unvault_txid,
                    label=f"trigger_r{round_num}",
                    amount_sats=unvault.amount_sats,
                ),
                rpc,
            )
            t_vsize = t_metrics.vsize or trigger_vsize  # fallback to Phase 1

            # Attacker front-runs with recovery
            r_record = adapter.recover(unvault)
            r_metrics = adapter.collect_tx_metrics(r_record, rpc)
            r_vsize = r_metrics.vsize or recover_vsize

            attacker_cumulative_vsize += r_vsize
            defender_cumulative_vsize += t_vsize

            rounds_completed = round_num

            if round_num <= 3 or round_num % 5 == 0 or round_num == MAX_GRIEF_ROUNDS:
                result.observe(
                    f"  Round {round_num}: trigger={t_vsize} vB, "
                    f"recover={r_vsize} vB  |  "
                    f"Cumulative: defender={defender_cumulative_vsize} vB, "
                    f"attacker={attacker_cumulative_vsize} vB"
                )

        except Exception as e:
            result.observe(f"  Round {round_num}: FAILED — {e}")
            break

    result.add_tx(TxMetrics(
        label="griefing_loop_totals",
        vsize=attacker_cumulative_vsize + defender_cumulative_vsize,
        fee_sats=0,
        num_inputs=rounds_completed,
        num_outputs=rounds_completed,
    ))

    # Asymmetry summary
    if attacker_cumulative_vsize > 0:
        actual_asymmetry = defender_cumulative_vsize / attacker_cumulative_vsize
        result.observe(
            f"After {rounds_completed} rounds: "
            f"defender spent {defender_cumulative_vsize} vB total, "
            f"attacker spent {attacker_cumulative_vsize} vB total.  "
            f"Ratio: {actual_asymmetry:.2f}x (defender pays more)."
        )
    result.observe(
        "NOTE: Defender also bears opportunity cost — each round delays "
        "the withdrawal by the full trigger-to-timeout cycle.  This cost "
        "is NOT captured in vsize but can dominate in practice."
    )

    # ── Phase 3: Fee-rate sensitivity ────────────────────────────────
    result.observe("=== Phase 3: Fee-rate sensitivity ===")

    fee_rates = [1, 5, 10, 50, 100, 500]

    for fee_rate in fee_rates:
        atk_cost_per_round = recover_vsize * fee_rate
        def_cost_per_round = trigger_vsize * fee_rate
        atk_10_rounds = atk_cost_per_round * 10
        def_10_rounds = def_cost_per_round * 10
        # How many rounds until defender has spent X% of vault?
        if def_cost_per_round > 0:
            rounds_to_1pct = int(VAULT_AMOUNT * 0.01 / def_cost_per_round)
            rounds_to_10pct = int(VAULT_AMOUNT * 0.10 / def_cost_per_round)
        else:
            rounds_to_1pct = rounds_to_10pct = 999999

        result.observe(
            f"  {fee_rate:>3} sat/vB: attacker={atk_cost_per_round:>8,} sats/round, "
            f"defender={def_cost_per_round:>8,} sats/round  |  "
            f"10 rounds: atk={atk_10_rounds:>9,}, def={def_10_rounds:>9,} sats  |  "
            f"Rounds to 1% vault: {rounds_to_1pct:,}, to 10%: {rounds_to_10pct:,}"
        )

    # ── Phase 4: spend_delay analysis ────────────────────────────────
    result.observe("=== Phase 4: spend_delay and timing window ===")

    spend_delay = getattr(adapter, "block_delay", None) or getattr(adapter, "locktime", 10)
    result.observe(
        f"  Current spend_delay = {spend_delay} blocks "
        f"(~{spend_delay * 10} min on mainnet)"
    )
    result.observe(
        "  spend_delay affects the griefing in TWO ways:"
    )
    result.observe(
        "  (1) ATTACKER TIMING: The attacker has spend_delay blocks to "
        "observe the mempool and broadcast recovery.  Longer delays give "
        "the attacker more time but don't change cost."
    )
    result.observe(
        "  (2) DEFENDER OPPORTUNITY COST: Each griefing round delays the "
        "withdrawal by ~spend_delay blocks.  Over N rounds, the total "
        "delay is N × spend_delay blocks.  Longer spend_delay = higher "
        "opportunity cost per round."
    )

    for delay in [5, 10, 20, 50, 144]:
        total_delay_10_rounds = delay * 10
        delay_hours = total_delay_10_rounds * 10 / 60
        result.observe(
            f"  spend_delay={delay}: 10 rounds = {total_delay_10_rounds} blocks "
            f"(~{delay_hours:.1f} hours).  Attacker timing window: {delay} blocks "
            f"(~{delay * 10} min)."
        )

    result.observe(
        "  INSIGHT: There is no spend_delay sweet spot.  Shorter delays "
        "reduce opportunity cost per round but give the attacker less time "
        "to observe the mempool (marginal benefit — mempool propagation is "
        "fast).  Longer delays make each griefing round more expensive in "
        "opportunity cost but don't change the vsize costs."
    )

    # ── Phase 5: Front-running advantage ─────────────────────────────
    result.observe("=== Phase 5: Mempool front-running advantage ===")

    result.observe(
        "  The attacker's key advantage: recovery requires NO key material "
        "on CCV.  Any node can broadcast recovery for any unvault UTXO."
    )
    result.observe(
        "  Front-running strategy: attacker monitors mempool for unvault "
        "transactions.  On detection, broadcasts recovery tx with a fee "
        "rate HIGHER than the unvault tx.  Miners rationally include the "
        "recovery (it spends the same UTXO but pays more fees)."
    )
    result.observe(
        "  The defender's counter: submit unvault + withdrawal atomically "
        "via package relay (BIP 331), or use out-of-band miner submission.  "
        "Neither is guaranteed, and both add complexity."
    )
    result.observe(
        "  The asymmetry between attacker and defender is threefold and "
        "empirically quantifiable: (1) trigger vsize > recovery vsize "
        f"({trigger_vsize} > {recover_vsize} vB, ratio {asymmetry:.2f}x), "
        "(2) defender bears opportunity cost of delayed withdrawal, "
        "(3) attacker has first-mover advantage via mempool monitoring."
    )
    result.observe(
        "  COMPARISON: CCV griefing is a liveness attack (withdrawal delay "
        "and fee cost).  CTV's combined fee_pinning + hot key attack risks "
        "fund loss.  The relative severity depends on deployment context — "
        "indefinite liveness denial may be operationally severe for users "
        "who need timely fund access."
    )


def _run_ctv_griefing(adapter, result, rpc):
    """CTV: Demonstrate the reverse griefing direction.

    On CTV, the griefing works differently: an attacker with the HOT KEY
    repeatedly triggers unvault, forcing the defender to sweep to cold
    each time.  The defender (watchtower) must broadcast tocold before the
    CSV timelock expires on each round.

    This is the CTV analog of CCV's forced-recovery griefing — but it
    requires a compromised hot key, whereas CCV's attack needs no keys.
    """
    result.observe("=== CTV Forced-Sweep Griefing ===")
    result.observe(
        "On CTV, the griefing direction is reversed: the ATTACKER triggers "
        "unvault (requires hot key on CTV), and the DEFENDER must sweep to "
        "cold (tocold) before the CSV timelock expires."
    )

    # ── Phase 1: Measure costs ───────────────────────────────────────
    result.observe("=== Phase 1: Measure trigger and cold-sweep vsize ===")

    vault = adapter.create_vault(VAULT_AMOUNT)
    result.observe(f"Vault created: {vault.vault_txid[:16]}... ({vault.amount_sats} sats)")

    unvault = adapter.trigger_unvault(vault)
    unvault_info = rpc.get_tx_info(unvault.unvault_txid)
    trigger_vsize = unvault_info.get("vsize", 0)
    result.observe(f"Unvault tx (attacker's cost): {trigger_vsize} vB")

    # Defender sweeps to cold
    cold_record = adapter.recover(unvault)
    cold_metrics = adapter.collect_tx_metrics(cold_record, rpc)
    cold_vsize = cold_metrics.vsize or 0
    result.observe(f"tocold tx (defender's cost): {cold_vsize} vB")
    result.add_tx(cold_metrics)

    if trigger_vsize > 0 and cold_vsize > 0:
        asymmetry = trigger_vsize / cold_vsize
        result.observe(
            f"Cost asymmetry: attacker_trigger/defender_sweep = "
            f"{trigger_vsize}/{cold_vsize} = {asymmetry:.2f}x"
        )
    else:
        asymmetry = 1.0

    # ── Phase 2: CTV griefing loop ───────────────────────────────────
    result.observe(f"=== Phase 2: CTV griefing loop ({MAX_GRIEF_ROUNDS} rounds) ===")
    result.observe(
        "NOTE: On CTV, the attacker needs the HOT KEY to trigger unvault.  "
        "This is a HIGHER bar than CCV's keyless recovery griefing."
    )

    attacker_cumulative = 0
    defender_cumulative = 0
    rounds_completed = 0

    for round_num in range(1, MAX_GRIEF_ROUNDS + 1):
        try:
            vault = adapter.create_vault(VAULT_AMOUNT)
            unvault = adapter.trigger_unvault(vault)

            u_info = rpc.get_tx_info(unvault.unvault_txid)
            t_vsize = u_info.get("vsize", trigger_vsize)

            cold = adapter.recover(unvault)
            c_metrics = adapter.collect_tx_metrics(cold, rpc)
            c_vsize = c_metrics.vsize or cold_vsize

            attacker_cumulative += t_vsize
            defender_cumulative += c_vsize
            rounds_completed = round_num

            if round_num <= 3 or round_num % 5 == 0 or round_num == MAX_GRIEF_ROUNDS:
                result.observe(
                    f"  Round {round_num}: trigger={t_vsize} vB, "
                    f"sweep={c_vsize} vB  |  "
                    f"Cumulative: attacker={attacker_cumulative} vB, "
                    f"defender={defender_cumulative} vB"
                )

        except Exception as e:
            result.observe(f"  Round {round_num}: FAILED — {e}")
            break

    if attacker_cumulative > 0 and defender_cumulative > 0:
        actual_ratio = attacker_cumulative / defender_cumulative
        result.observe(
            f"After {rounds_completed} rounds: attacker={attacker_cumulative} vB, "
            f"defender={defender_cumulative} vB.  Ratio: {actual_ratio:.2f}x."
        )

    # ── Phase 3: Cross-design comparison ─────────────────────────────
    result.observe("=== Phase 3: CTV vs CCV griefing comparison ===")
    result.observe(
        "  CTV griefing: Requires HOT KEY.  Attacker triggers unvault, "
        "defender sweeps to cold.  Funds remain safe (in cold storage)."
    )
    result.observe(
        "  CCV griefing: Requires NO KEY.  Attacker calls recover on any "
        "unvault.  Defender must re-trigger.  Funds remain safe (in vault)."
    )
    result.observe(
        "  KEY DIFFERENCE: CCV's attack surface is WIDER (anyone can grief) "
        "but the consequence is the SAME (liveness denial, never fund loss).  "
        "CTV's griefing surface is narrower (needs hot key) but if the "
        "attacker also has the fee key, it escalates to fund theft (see "
        "fee_pinning experiment)."
    )

    # Fee rate analysis
    result.observe("=== Phase 4: Fee-rate sensitivity (CTV) ===")
    for fee_rate in [1, 10, 50, 100]:
        atk_cost = trigger_vsize * fee_rate
        def_cost = cold_vsize * fee_rate
        result.observe(
            f"  {fee_rate:>3} sat/vB: attacker={atk_cost:>7,} sats/round, "
            f"defender={def_cost:>7,} sats/round"
        )


def _run_trigger_recover_griefing(adapter, result, rpc):
    """Generic griefing loop for CCV, OP_VAULT, and CAT+CSFS.

    All three share the same structure: measure costs → run N rounds of
    create vault → trigger → recover → report. The only differences are
    the intro observations and comparison text, which are parameterized here.

    CCV:      Attacker (no key) calls recover → Defender re-triggers
    OP_VAULT: Attacker (recoveryauth key) calls recover → Defender re-triggers
    CAT+CSFS: Attacker (hot key) triggers unvault → Defender recovers with cold key
    """
    covenant = adapter.name

    # Per-covenant intro observations
    INTROS = {
        "ccv": [],  # CCV intro is handled in _run_ccv_griefing
        "opvault": [
            "=== OP_VAULT Authorized Recovery Griefing ===",
            "On OP_VAULT, recovery griefing requires the RECOVERYAUTH KEY.  "
            "This is OP_VAULT's explicit anti-griefing design: unlike CCV where "
            "anyone can call recover, OP_VAULT demands a Schnorr signature from "
            "the recoveryauth private key.",
        ],
        "cat_csfs": [
            "=== CAT+CSFS Recovery Griefing (hot key required) ===",
            "On CAT+CSFS, an attacker with the HOT KEY can trigger unvault, "
            "forcing the defender to recover with the COLD KEY before the CSV "
            "timelock expires.  This is analogous to CTV's hot-key griefing.",
        ],
    }

    for note in INTROS.get(covenant, []):
        result.observe(note)

    # ── Phase 1: Measure baseline costs ──────────────────────────────
    result.observe("=== Phase 1: Measure trigger and recovery vsize ===")

    vault = adapter.create_vault(VAULT_AMOUNT)
    result.observe(f"Vault created: {vault.vault_txid[:16]}... ({vault.amount_sats} sats)")

    unvault = adapter.trigger_unvault(vault)
    trigger_metrics = adapter.collect_tx_metrics(
        TxRecord(
            txid=unvault.unvault_txid,
            label="trigger",
            amount_sats=unvault.amount_sats,
        ),
        rpc,
    )
    trigger_vsize = trigger_metrics.vsize or 0
    result.observe(f"Trigger tx: {unvault.unvault_txid[:16]}... ({trigger_vsize} vB)")
    result.add_tx(trigger_metrics)

    recover_record = adapter.recover(unvault)
    recover_metrics = adapter.collect_tx_metrics(recover_record, rpc)
    recover_vsize = recover_metrics.vsize or 0
    result.observe(f"Recovery tx: {recover_record.txid[:16]}... ({recover_vsize} vB)")
    result.add_tx(recover_metrics)

    # Cost asymmetry
    if trigger_vsize > 0 and recover_vsize > 0:
        asymmetry = trigger_vsize / recover_vsize
        result.observe(
            f"Cost asymmetry: trigger/recovery = {trigger_vsize}/{recover_vsize} "
            f"= {asymmetry:.2f}x"
        )
    else:
        asymmetry = 1.0
        result.observe("WARNING: Could not measure recovery vsize — using 1.0x asymmetry")

    # ── Phase 2: Griefing loop ───────────────────────────────────────
    result.observe(f"=== Phase 2: Griefing loop ({MAX_GRIEF_ROUNDS} rounds) ===")

    # For CAT+CSFS, attacker pays trigger cost; defender pays recover cost
    # For CCV/OP_VAULT, attacker pays recover cost; defender pays trigger cost
    attacker_is_trigger = covenant == "cat_csfs"

    attacker_cumulative = 0
    defender_cumulative = 0
    rounds_completed = 0

    for round_num in range(1, MAX_GRIEF_ROUNDS + 1):
        try:
            vault = adapter.create_vault(VAULT_AMOUNT)
            unvault = adapter.trigger_unvault(vault)

            t_metrics = adapter.collect_tx_metrics(
                TxRecord(txid=unvault.unvault_txid, label=f"trigger_r{round_num}",
                         amount_sats=unvault.amount_sats), rpc)
            t_vsize = t_metrics.vsize or trigger_vsize

            r_record = adapter.recover(unvault)
            r_metrics = adapter.collect_tx_metrics(r_record, rpc)
            r_vsize = r_metrics.vsize or recover_vsize

            if attacker_is_trigger:
                attacker_cumulative += t_vsize
                defender_cumulative += r_vsize
            else:
                attacker_cumulative += r_vsize
                defender_cumulative += t_vsize

            rounds_completed = round_num

            if round_num <= 3 or round_num % 5 == 0 or round_num == MAX_GRIEF_ROUNDS:
                result.observe(
                    f"  Round {round_num}: trigger={t_vsize} vB, "
                    f"recover={r_vsize} vB  |  "
                    f"Cumulative: attacker={attacker_cumulative} vB, "
                    f"defender={defender_cumulative} vB"
                )

        except Exception as e:
            result.observe(f"  Round {round_num}: FAILED — {e}")
            break

    result.add_tx(TxMetrics(
        label="griefing_loop_totals",
        vsize=attacker_cumulative + defender_cumulative,
        fee_sats=0,
        num_inputs=rounds_completed,
        num_outputs=rounds_completed,
    ))

    if attacker_cumulative > 0 and defender_cumulative > 0:
        actual_ratio = defender_cumulative / attacker_cumulative
        result.observe(
            f"After {rounds_completed} rounds: "
            f"defender spent {defender_cumulative} vB total, "
            f"attacker spent {attacker_cumulative} vB total.  "
            f"Ratio: {actual_ratio:.2f}x."
        )

    result.observe(
        "NOTE: Defender also bears opportunity cost — each round delays "
        "the withdrawal by the full trigger-to-timeout cycle."
    )

    # ── Phase 3: Spend delay analysis ─────────────────────────────────
    spend_delay = getattr(adapter, "block_delay", None) or getattr(adapter, "locktime", 10)
    result.observe(f"=== Phase 3: Timing (spend_delay={spend_delay} blocks) ===")
    for delay in [5, 10, 20, 50, 144]:
        total = delay * 10
        hours = total * 10 / 60
        result.observe(
            f"  spend_delay={delay}: 10 rounds = {total} blocks (~{hours:.1f} hours)"
        )

    # ── Phase 4: Four-way comparison ──────────────────────────────────
    result.observe("=== Phase 4: Four-way griefing comparison ===")
    result.observe(
        "  CCV:      Keyless recovery — NO key needed.  Bar: ZERO."
    )
    result.observe(
        "  OP_VAULT: Authorized recovery — recoveryauth key needed.  Bar: key compromise."
    )
    result.observe(
        "  CTV:      Hot-key sweep — hot key needed (reverse direction).  "
        "            Can escalate to fund theft with fee key."
    )
    result.observe(
        "  CAT+CSFS: Hot-key trigger — hot key needed (same direction as CTV).  "
        "            CANNOT escalate (no fee key / anchor outputs)."
    )
    result.observe(
        "  HIERARCHY (by escalation severity): "
        "CTV > CCV > CAT+CSFS > OP_VAULT"
    )
    result.observe(
        "  INVERSE HIERARCHY (fund safety under key loss): "
        "CCV > CTV > CAT+CSFS > OP_VAULT"
    )

    # ── Phase 5: Fee-rate sensitivity ─────────────────────────────────
    atk_vsize = trigger_vsize if attacker_is_trigger else recover_vsize
    def_vsize = recover_vsize if attacker_is_trigger else trigger_vsize
    result.observe(f"=== Phase 5: Fee-rate sensitivity ({covenant.upper()}) ===")
    for fee_rate in [1, 10, 50, 100, 500]:
        atk_cost = atk_vsize * fee_rate
        def_cost = def_vsize * fee_rate
        result.observe(
            f"  {fee_rate:>3} sat/vB: attacker={atk_cost:>8,} sats/round, "
            f"defender={def_cost:>8,} sats/round"
        )

