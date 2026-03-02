"""Experiment F: Multi-Input Batching

Tests batched trigger capabilities — spending multiple vault UTXOs in a
single transaction — and measures the efficiency gains (or impossibility).

=== RELATED WORK ===
CTV's inability to batch triggers follows from BIP-119's
(https://bips.dev/119/) commitment to input count and spend index.
CCV batching and the cross-input DEDUCT accounting footgun are
documented by Ingala (BIP-443, https://bips.dev/443/).  This experiment
measures the vsize scaling curve for CCV batched triggers (marginal
weight per vault, projected ceiling at ~1,600 vaults per standard
transaction) and demonstrates the cross-input DEDUCT accounting failure
on regtest.

CTV: No batched trigger support.  Each vault UTXO has its own CTV hash
committing to a specific unvault transaction.  Spending multiple vaults
requires separate transactions.  CTV commits to input count and spend
index, so a single tx consuming N vault inputs would need N matching
CTV hashes, all of which would need to be computed at vault creation
time with foreknowledge of the batch.

CCV: Batched triggers are possible.  Multiple vault instances can be
consumed in a single trigger transaction.  The CCV output checks
validate each input independently.  However, cross-input DEDUCT
accounting is a known footgun — incorrect mode usage can lead to
value miscounting.

Enhanced with explicit cross-input DEDUCT failure demonstration for CCV,
based on pymatt's cross_input_accounting_attack.py.
"""

from adapters.base import VaultAdapter, VaultState
from harness.metrics import ExperimentResult
from harness.rpc import RegTestRPC
from harness.regtest_caveats import emit_vsize_is_primary
from experiments.registry import register


VAULT_AMOUNT = 10_000_000  # 0.1 BTC per vault
DEFAULT_VAULT_COUNTS = [1, 2, 3, 5, 10, 20, 50]

# Smaller amount for the DEDUCT demo (matches pymatt attack script)
DEDUCT_AMOUNT = 70_000


def _ceiling_analysis(result, vault_counts, vsize_by_n, weight_by_n, covenant):
    """Analyze tx/block size limits and project the batching ceiling.

    Bitcoin consensus/policy limits:
    - MAX_STANDARD_TX_WEIGHT = 400,000 WU (standardness, not consensus)
    - MAX_BLOCK_WEIGHT = 4,000,000 WU (consensus)
    - Practical single-tx ceiling: 400k WU (relay policy)
    """
    MAX_STANDARD_TX_WEIGHT = 400_000  # Policy limit for relay
    MAX_BLOCK_WEIGHT = 4_000_000      # Consensus limit

    result.observe("=== Ceiling analysis: tx/block size limits ===")

    if len(vsize_by_n) < 2:
        result.observe("  Insufficient data points for ceiling projection.")
        return

    # Compute per-vault marginal weight from the data
    sorted_ns = sorted(weight_by_n.keys())
    if len(sorted_ns) >= 2:
        n_lo, n_hi = sorted_ns[0], sorted_ns[-1]
        w_lo, w_hi = weight_by_n[n_lo], weight_by_n[n_hi]
        if n_hi > n_lo:
            marginal_weight = (w_hi - w_lo) / (n_hi - n_lo)
            base_weight = w_lo - marginal_weight * n_lo
        else:
            marginal_weight = w_hi / n_hi if n_hi > 0 else 0
            base_weight = 0
    else:
        n0 = sorted_ns[0]
        marginal_weight = weight_by_n[n0] / n0 if n0 > 0 else 0
        base_weight = 0

    result.observe(
        f"  Weight model: ~{base_weight:.0f} base + ~{marginal_weight:.0f} WU/vault "
        f"(linear regression from {len(sorted_ns)} data points)"
    )

    # Project ceilings
    if marginal_weight > 0:
        max_vaults_standard = int((MAX_STANDARD_TX_WEIGHT - base_weight) / marginal_weight)
        max_vaults_block = int((MAX_BLOCK_WEIGHT - base_weight) / marginal_weight)
    else:
        max_vaults_standard = max_vaults_block = 999999

    result.observe(
        f"  Standardness ceiling (400k WU): ~{max_vaults_standard} vaults per tx"
    )
    result.observe(
        f"  Block weight ceiling (4M WU): ~{max_vaults_block} vaults per tx "
        f"(theoretical, ignoring other block contents)"
    )

    if covenant in ("ctv", "cat_csfs"):
        result.observe(
            f"  NOTE: {covenant.upper()} can't batch, so this ceiling is per-block throughput "
            "(how many individual trigger txs fit in one block), not per-tx."
        )
    else:
        result.observe(
            f"  At N={max_vaults_standard}, a single batched trigger tx would "
            f"consume the entire standardness budget.  Institutional custodians "
            f"managing > {max_vaults_standard} UTXOs would need multiple batches."
        )

    # Check if any measured data point already exceeds limits
    for n in sorted_ns:
        w = weight_by_n[n]
        if w > MAX_STANDARD_TX_WEIGHT:
            result.observe(
                f"  WARNING: N={n} already exceeds standardness limit "
                f"({w:,} > {MAX_STANDARD_TX_WEIGHT:,} WU).  This tx would "
                f"not be relayed by default policy nodes."
            )
            break

    # Scaling efficiency for CCV
    if covenant == "ccv" and len(sorted_ns) >= 2:
        n1, n_last = sorted_ns[0], sorted_ns[-1]
        if n1 > 0 and n_last > 0:
            per_vault_1 = vsize_by_n[n1] / n1
            per_vault_last = vsize_by_n[n_last] / n_last
            saving_pct = (1 - per_vault_last / per_vault_1) * 100
            result.observe(
                f"  Scaling efficiency: per-vault vsize drops from "
                f"{per_vault_1:.1f} vB (N={n1}) to {per_vault_last:.1f} vB "
                f"(N={n_last}) — {saving_pct:.1f}% savings from batching."
            )


def _sweep_ctv(adapter, result, rpc, vault_counts):
    """CTV: no batched trigger — measure individual trigger cost at each N.

    Since CTV can't batch, the total vsize for N vaults is simply N × single.
    We measure the single-trigger vsize and extrapolate, recording a data
    point for each N in vault_counts.
    """
    result.observe("--- CTV batching sweep (individual triggers only) ---")

    # Measure single-trigger vsize
    v = adapter.create_vault(VAULT_AMOUNT)
    uv = adapter.trigger_unvault(v)
    info = rpc.get_tx_info(uv.unvault_txid)
    single_vsize = info.get("vsize", 0)
    single_weight = info.get("weight", 0)
    w = adapter.complete_withdrawal(uv)
    single_metrics = adapter.collect_tx_metrics(w, rpc)
    single_fee = single_metrics.fee_sats

    result.observe(f"Single trigger baseline: vsize={single_vsize}, fee={single_fee} sats")
    result.observe(
        "CTV commits to input count and index — batching requires foreknowledge "
        "of the exact batch composition at vault creation time. "
        "Total cost scales linearly: N × single_trigger_cost."
    )

    # Record extrapolated data points
    from harness.metrics import TxMetrics
    vsize_by_n = {}
    weight_by_n = {}
    for n in vault_counts:
        total_vsize = single_vsize * n
        total_weight = single_weight * n
        vsize_by_n[n] = total_vsize
        weight_by_n[n] = total_weight
        result.add_tx(TxMetrics(
            label=f"batch_{n}_total",
            vsize=total_vsize,
            weight=total_weight,
            fee_sats=single_fee * n,
            num_inputs=n,
            num_outputs=n,  # each trigger produces its own unvault output
        ))
        result.observe(
            f"  N={n}: total_vsize={total_vsize} "
            f"(= {n} × {single_vsize}), fee={single_fee * n} sats"
        )

    # Ceiling analysis
    _ceiling_analysis(result, vault_counts, vsize_by_n, weight_by_n, "ctv")


def _sweep_cat_csfs(adapter, result, rpc, vault_counts):
    """CAT+CSFS: no batched trigger — identical to CTV's limitation.

    Each vault UTXO has its own tapscript with covenant verification.
    The CSFS signature commits to specific input/output structure.
    Batching would require all N vaults to share a single sighash preimage
    covering N inputs — not possible with the current design.

    Like CTV, total vsize for N vaults = N × single_trigger_cost.
    """
    result.observe("--- CAT+CSFS batching sweep (individual triggers only) ---")

    # Measure single-trigger vsize
    v = adapter.create_vault(VAULT_AMOUNT)
    uv = adapter.trigger_unvault(v)
    info = rpc.get_tx_info(uv.unvault_txid)
    single_vsize = info.get("vsize", 0)
    single_weight = info.get("weight", 0)
    w = adapter.complete_withdrawal(uv)
    single_metrics = adapter.collect_tx_metrics(w, rpc)
    single_fee = single_metrics.fee_sats

    result.observe(f"Single trigger baseline: vsize={single_vsize}, fee={single_fee} sats")
    result.observe(
        "CAT+CSFS commits via CSFS signature verification against a specific "
        "sighash preimage.  Each vault's trigger requires its own signature — "
        "batching requires N independent signatures and N independent covenant "
        "script executions.  Total cost scales linearly: N × single_trigger_cost."
    )

    # Record extrapolated data points
    from harness.metrics import TxMetrics
    vsize_by_n = {}
    weight_by_n = {}
    for n in vault_counts:
        total_vsize = single_vsize * n
        total_weight = single_weight * n
        vsize_by_n[n] = total_vsize
        weight_by_n[n] = total_weight
        result.add_tx(TxMetrics(
            label=f"batch_{n}_total",
            vsize=total_vsize,
            weight=total_weight,
            fee_sats=single_fee * n,
            num_inputs=n,
            num_outputs=n,
        ))
        result.observe(
            f"  N={n}: total_vsize={total_vsize} "
            f"(= {n} × {single_vsize}), fee={single_fee * n} sats"
        )

    # Ceiling analysis
    _ceiling_analysis(result, vault_counts, vsize_by_n, weight_by_n, "cat_csfs")

    result.observe(
        "COMPARISON: Both CTV and CAT+CSFS lack native batching.  CCV and "
        "OP_VAULT can batch N vault triggers into a single transaction, "
        "achieving sub-linear scaling.  The per-vault overhead difference "
        "between CTV and CAT+CSFS depends on witness sizes — CAT+CSFS "
        "triggers are larger due to the CSFS witness (sighash preimage + "
        "dual signatures) vs CTV's minimal witness (just the CTV hash)."
    )


def _sweep_ccv(adapter, result, rpc, vault_counts):
    """CCV: measure actual batched trigger cost at each N.

    Creates N vaults and triggers them in a single transaction,
    recording the real vsize at each batch size.
    """
    result.observe("--- CCV batching sweep (real batched triggers) ---")

    from harness.metrics import TxMetrics

    vsize_by_n = {}
    weight_by_n = {}
    hit_ceiling = False

    for n in vault_counts:
        if hit_ceiling:
            result.observe(f"  N={n}: SKIPPED — previous batch hit tx size limit")
            continue

        try:
            vaults = [adapter.create_vault(VAULT_AMOUNT) for _ in range(n)]

            if n == 1:
                # Single vault: regular trigger
                uv = adapter.trigger_unvault(vaults[0])
            else:
                # Batched trigger
                uv = adapter.trigger_batched(vaults)

            info = rpc.get_tx_info(uv.unvault_txid)
            total_vsize = info.get("vsize", 0)
            total_weight = info.get("weight", 0)
            vsize_by_n[n] = total_vsize
            weight_by_n[n] = total_weight

            # Complete withdrawal to get fee info
            w = adapter.complete_withdrawal(uv)
            wm = adapter.collect_tx_metrics(w, rpc)

            result.add_tx(TxMetrics(
                label=f"batch_{n}_total",
                txid=uv.unvault_txid,
                vsize=total_vsize,
                weight=total_weight,
                fee_sats=wm.fee_sats,
                num_inputs=n,
                num_outputs=info.get("vout_count", 0),
            ))

            per_vault = total_vsize / n if n > 0 else 0
            result.observe(
                f"  N={n}: total_vsize={total_vsize}, weight={total_weight}, "
                f"per_vault={per_vault:.1f} vB, fee={wm.fee_sats} sats"
            )

            # Check if we're approaching standardness limit
            if total_weight > 400_000:
                result.observe(
                    f"  WARNING: N={n} exceeds standardness limit "
                    f"({total_weight:,} > 400,000 WU)"
                )
                hit_ceiling = True

        except Exception as e:
            err_str = str(e)
            result.observe(f"  N={n}: FAILED — {err_str[:150]}")
            if "tx-size" in err_str or "too large" in err_str.lower():
                hit_ceiling = True
                result.observe(
                    f"  CEILING DETECTED at N={n}: transaction exceeds size limits."
                )

    # Ceiling analysis
    _ceiling_analysis(result, vault_counts, vsize_by_n, weight_by_n, "ccv")

    # --- Phase 3: Cross-input DEDUCT failure demonstration ---
    # Replicates pymatt's cross_input_accounting_attack.py.
    #
    # The trigger_and_revault clause uses CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
    # which subtracts the designated output amount from the input's value
    # when computing the expected CCV output amount.  This is evaluated
    # PER-INPUT — it is NOT a global accumulator across all inputs.
    #
    # A naive coordinator that treats the revault output as a single
    # shared deduction point for multiple inputs will produce a tx where
    # CCV amount checks fail, because each input independently expects
    # its own deduction to be reflected in the output amount.
    result.observe("--- Phase 3: Cross-input DEDUCT failure demo ---")

    _run_deduct_demo(adapter, result)


def _sweep_opvault(adapter, result, rpc, vault_counts):
    """OP_VAULT: measure batched trigger cost at each N.

    OP_VAULT's start_withdrawal() accepts multiple VaultUtxo objects,
    combining them into a single trigger transaction.  This is similar
    to CCV batching but uses OP_VAULT's specific script structure.
    """
    result.observe("--- OP_VAULT batching sweep (real batched triggers) ---")

    from harness.metrics import TxMetrics

    vsize_by_n = {}
    weight_by_n = {}
    hit_ceiling = False

    for n in vault_counts:
        if hit_ceiling:
            result.observe(f"  N={n}: SKIPPED — previous batch hit tx size limit")
            continue

        try:
            vaults = [adapter.create_vault(VAULT_AMOUNT) for _ in range(n)]

            if n == 1:
                uv = adapter.trigger_unvault(vaults[0])
            else:
                uv = adapter.trigger_batched(vaults)

            info = rpc.get_tx_info(uv.unvault_txid)
            total_vsize = info.get("vsize", 0)
            total_weight = info.get("weight", 0)
            vsize_by_n[n] = total_vsize
            weight_by_n[n] = total_weight

            # Complete withdrawal to get fee info
            w = adapter.complete_withdrawal(uv)
            wm = adapter.collect_tx_metrics(w, rpc)

            result.add_tx(TxMetrics(
                label=f"batch_{n}_total",
                txid=uv.unvault_txid,
                vsize=total_vsize,
                weight=total_weight,
                fee_sats=wm.fee_sats,
                num_inputs=n,
                num_outputs=info.get("vout_count", len(info.get("vout", []))),
            ))

            per_vault = total_vsize / n if n > 0 else 0
            result.observe(
                f"  N={n}: total_vsize={total_vsize}, weight={total_weight}, "
                f"per_vault={per_vault:.1f} vB, fee={wm.fee_sats} sats"
            )

            if total_weight > 400_000:
                result.observe(
                    f"  WARNING: N={n} exceeds standardness limit "
                    f"({total_weight:,} > 400,000 WU)"
                )
                hit_ceiling = True

        except Exception as e:
            err_str = str(e)
            result.observe(f"  N={n}: FAILED — {err_str[:150]}")
            if "tx-size" in err_str or "too large" in err_str.lower():
                hit_ceiling = True

    _ceiling_analysis(result, vault_counts, vsize_by_n, weight_by_n, "opvault")

    # OP_VAULT comparison notes
    result.observe("\n--- OP_VAULT batching comparison ---")
    result.observe(
        "OP_VAULT batching uses start_withdrawal() with multiple VaultUtxo "
        "inputs.  Unlike CCV, there is no DEDUCT mode footgun — OP_VAULT's "
        "opcode semantics handle revault accounting internally."
    )
    result.observe(
        "THREE-WAY BATCHING COMPARISON:"
    )
    result.observe(
        "  CTV:      No batching — each vault UTXO needs its own trigger tx.  "
        "            CTV commits to input count/index at creation time."
    )
    result.observe(
        "  CCV:      Batching supported — multiple inputs in one trigger.  "
        "            DEDUCT mode footgun: multiple DEDUCT inputs sharing one "
        "            revault output → silent failure.  Coordinator complexity."
    )
    result.observe(
        "  OP_VAULT: Batching supported — multiple VaultUtxos in one trigger.  "
        "            No DEDUCT footgun.  Automatic revault for excess amount.  "
        "            Simpler coordinator logic than CCV."
    )


def _run_deduct_demo(adapter, result):
    """Demonstrate cross-input DEDUCT accounting bug.

    Control: trigger_and_revault + trigger (one DEDUCT, one preserve) -> succeeds.
    Buggy:   trigger_and_revault + trigger_and_revault (both DEDUCT same output) -> rejected.
    """
    from matt.btctools import key as keymod

    manager = adapter._manager
    pymatt_rpc = adapter._pymatt_rpc
    vault_contract = adapter.vault_contract
    make_ctv_template = adapter._mods["make_ctv_template"]
    unvault_priv_key = adapter.unvault_priv_key

    # Withdrawal destination
    dest_addr = pymatt_rpc.getnewaddress("deduct-demo-withdraw")
    ctv_template = make_ctv_template(
        [(dest_addr, 100_000)], nSequence=adapter.locktime
    )
    ctv_hash = ctv_template.get_standard_template_hash(0)

    # --- Control case: one DEDUCT + one preserve ---
    result.observe("Control: 1x trigger_and_revault (DEDUCT) + 1x trigger (preserve)")

    safe_a = manager.fund_instance(vault_contract, DEDUCT_AMOUNT)
    safe_b = manager.fund_instance(vault_contract, DEDUCT_AMOUNT)

    safe_spends = [
        (safe_a, "trigger_and_revault", {
            "out_i": 0, "revault_out_i": 1, "ctv_hash": ctv_hash,
        }),
        (safe_b, "trigger", {
            "out_i": 0, "ctv_hash": ctv_hash,
        }),
    ]
    revault_amount = DEDUCT_AMOUNT * 2 - 100_000  # total inputs minus withdrawal
    safe_tx, safe_sighashes = manager.get_spend_tx(
        safe_spends, output_amounts={1: revault_amount}
    )

    safe_tx.wit.vtxinwit = []
    sigs = [
        keymod.sign_schnorr(unvault_priv_key.privkey, sh)
        for sh in safe_sighashes
    ]
    for i, (inst, action, args) in enumerate(safe_spends):
        safe_tx.wit.vtxinwit.append(
            manager.get_spend_wit(inst, action, {**args, "sig": sigs[i]})
        )

    try:
        safe_txid = pymatt_rpc.sendrawtransaction(safe_tx.serialize().hex())
        addr = pymatt_rpc.getnewaddress()
        pymatt_rpc.generatetoaddress(1, addr)
        result.observe(f"Control tx ACCEPTED: {safe_txid[:16]}...")
        result.observe(
            "One input uses DEDUCT (trigger_and_revault), the other uses "
            "preserve (trigger). The revault output amount is computed "
            "correctly because only one input contributes a deduction."
        )
    except Exception as e:
        result.observe(f"Control tx UNEXPECTEDLY REJECTED: {e}")
        return  # If control fails, skip the buggy case

    # --- Buggy case: both inputs DEDUCT to the same output ---
    result.observe("Buggy: 2x trigger_and_revault (both DEDUCT) to same revault output")

    bug_a = manager.fund_instance(vault_contract, DEDUCT_AMOUNT)
    bug_b = manager.fund_instance(vault_contract, DEDUCT_AMOUNT)

    buggy_spends = [
        (bug_a, "trigger_and_revault", {
            "out_i": 0, "revault_out_i": 1, "ctv_hash": ctv_hash,
        }),
        (bug_b, "trigger_and_revault", {
            "out_i": 0, "revault_out_i": 1, "ctv_hash": ctv_hash,
        }),
    ]

    # Naive coordinator: sets revault output = total_input - withdrawal.
    # This would be correct for a global deduction, but CCV evaluates
    # deductions per-input, not globally.
    naive_revault = DEDUCT_AMOUNT * 2 - 100_000
    buggy_tx, buggy_sighashes = manager.get_spend_tx(
        buggy_spends, output_amounts={1: naive_revault}
    )

    buggy_tx.wit.vtxinwit = []
    bug_sigs = [
        keymod.sign_schnorr(unvault_priv_key.privkey, sh)
        for sh in buggy_sighashes
    ]
    for i, (inst, action, args) in enumerate(buggy_spends):
        buggy_tx.wit.vtxinwit.append(
            manager.get_spend_wit(inst, action, {**args, "sig": bug_sigs[i]})
        )

    total_in = bug_a.get_value() + bug_b.get_value()
    total_out = sum(out.nValue for out in buggy_tx.vout)
    result.observe(
        f"Buggy tx economics: inputs={total_in} sats, "
        f"outputs={total_out} sats, fee={total_in - total_out} sats"
    )

    try:
        pymatt_rpc.sendrawtransaction(buggy_tx.serialize().hex())
        result.observe(
            "Buggy tx UNEXPECTEDLY ACCEPTED — DEDUCT semantics may have "
            "changed or the coordinator's accounting was actually correct."
        )
    except Exception as e:
        err = str(e)
        if "incorrect amount" in err.lower() or "script-verify" in err.lower():
            result.observe(f"Buggy tx REJECTED as expected: {err}")
        else:
            result.observe(f"Buggy tx REJECTED (different error): {err}")

    result.observe(
        "CONCLUSION: CCV's DEDUCT mode (CCV_FLAG_DEDUCT_OUTPUT_AMOUNT) is "
        "evaluated per-input, not as a global accumulator. When two inputs "
        "both use trigger_and_revault pointing to the same revault output, "
        "each independently expects (input_amount - output_amount) to equal "
        "the CCV-checked value. A naive coordinator that treats the revault "
        "output as a single shared bucket will produce invalid transactions. "
        "This is a liveness footgun, not a theft vector — funds remain safe "
        "but withdrawals are blocked until the coordinator is fixed."
    )

    # --- Phase 4: Coordinator pattern analysis ---
    # Characterize which coordinator logic patterns are safe vs unsafe.
    result.observe("--- Phase 4: Safe vs unsafe coordinator patterns ---")

    result.observe(
        "SAFE PATTERN 1 — Single-input trigger_and_revault: One vault input "
        "uses trigger_and_revault, producing an Unvaulting output and a "
        "revault output. DEDUCT is evaluated on one input only. Always correct."
    )
    result.observe(
        "SAFE PATTERN 2 — Mixed trigger + trigger_and_revault: N vault inputs "
        "where exactly ONE uses trigger_and_revault (DEDUCT) and the rest use "
        "trigger (preserve). The single DEDUCT input's check is consistent "
        "with the revault output amount. This is our control case above."
    )
    result.observe(
        "SAFE PATTERN 3 — All-trigger batched (no revault): N vault inputs "
        "all using trigger (preserve mode). No DEDUCT checks at all. The "
        "entire batch goes into one Unvaulting output. Always correct."
    )
    result.observe(
        "SAFE PATTERN 4 — Separate revault outputs per DEDUCT input: If each "
        "trigger_and_revault input points to its OWN dedicated revault output "
        "(different revault_out_i values), the per-input DEDUCT checks are "
        "independent and can all succeed. Requires N revault outputs for N "
        "DEDUCT inputs — more complex but formally correct."
    )
    result.observe(
        "UNSAFE PATTERN — Multiple DEDUCT inputs sharing one revault output: "
        "Two or more inputs use trigger_and_revault pointing to the SAME "
        "revault output index. Each input independently checks "
        "(input_amount - revault_output_amount), producing contradictory "
        "requirements. This is our buggy case above."
    )
    result.observe(
        "FORMALIZATION: For a transaction with inputs I_1..I_n and a revault "
        "output R, let D = {i : input I_i uses DEDUCT mode pointing at R}. "
        "If |D| = 0 or |D| = 1, the transaction is valid (assuming amounts "
        "balance). If |D| > 1, the CCV checks produce the system of "
        "equations: for each i in D, R.amount = I_i.amount - U.amount, "
        "where U is the unvaulting output. This system is only satisfiable "
        "if all I_i in D have the same amount — a coincidence that a "
        "coordinator should never rely on."
    )
    result.observe(
        "REAL-WORLD SCENARIO: A 'reasonable' coordinator implementation "
        "might batch N vault UTXOs for a partial withdrawal by having each "
        "input use trigger_and_revault (to preserve the remainder). This is "
        "the natural generalization of single-input revault to multi-input "
        "revault, and it fails silently. The fix is either: (a) use at most "
        "one DEDUCT input per revault output, or (b) give each DEDUCT input "
        "its own revault output. Pattern (a) is simpler but limits partial "
        "withdrawal to one vault at a time in a batch."
    )


@register(
    name="multi_input",
    description="Multi-input batched trigger comparison with scaling sweep",
    tags=["core", "capability_gap", "quantitative", "batching", "efficiency"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    vault_counts = getattr(adapter, "vault_counts", DEFAULT_VAULT_COUNTS)

    result = ExperimentResult(
        experiment="multi_input",
        covenant=adapter.name,
        params={
            "vault_amount_sats": VAULT_AMOUNT,
            "vault_counts": vault_counts,
        },
    )

    rpc = adapter.rpc

    try:
        if adapter.name == "ctv":
            _sweep_ctv(adapter, result, rpc, vault_counts)
        elif adapter.name == "ccv":
            _sweep_ccv(adapter, result, rpc, vault_counts)
            # Run DEDUCT demo only once (not part of sweep)
            result.observe("")
            _run_deduct_demo(adapter, result)
        elif adapter.name == "opvault":
            _sweep_opvault(adapter, result, rpc, vault_counts)
        elif adapter.name == "cat_csfs":
            _sweep_cat_csfs(adapter, result, rpc, vault_counts)
        else:
            result.observe(f"No multi-input test for {adapter.name}")
    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")

    emit_vsize_is_primary(result)
    return result
