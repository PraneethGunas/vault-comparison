"""Experiment D: Revault Amplification

Tests partial-withdrawal (revault) capabilities and measures amplification
effects — how many sequential partial spends can be chained from a single
initial vault, and what are the cumulative costs.

=== RELATED WORK ===
CCV's partial withdrawal via trigger_and_revault is a core feature of
BIP-443 [Ing23] (https://bips.dev/443/).  CTV's all-or-nothing unvault is
inherent to BIP-119 [Rub20] (https://bips.dev/119/).  OP_VAULT supports
partial withdrawal with automatic revault (BIP-345 [OS23],
https://bips.dev/345/): start_withdrawal with excess creates a revault
output.  The splitting-attack implications of revault are analyzed in
Harding [Har24] (https://delvingbitcoin.org/t/op-vault-comments/521) and
measured empirically in exp_watchtower_exhaustion.  This experiment measures
the cost AMPLIFICATION of sequential partial withdrawals — the cumulative
overhead of N partial withdrawals vs. a single full withdrawal.

CTV: No native revault support.  The entire vault amount must be unvaulted
at once.  Partial withdrawals require destroying and recreating the vault
with new CTV hashes.

CCV: Native revault via `trigger_and_revault` clause.  A single trigger
splits the vault into an Unvaulting output (for withdrawal) and a new
Vault output (holding the remainder).  This can be chained repeatedly.

OP_VAULT: Native partial withdrawal via start_withdrawal.  Excess value
beyond the CTV template is automatically revaulted.

CAT+CSFS: No native revault.  Like CTV, the full amount must be unvaulted
atomically.  Partial withdrawals require recovery + re-vaulting.

Key comparison points:
- Can the vault do partial withdrawals at all?
- What are the cumulative tx costs of N partial withdrawals?
- How does the remainder shrink across iterations?
"""

from adapters.base import VaultAdapter
from harness.metrics import ExperimentResult
from harness.regtest_caveats import emit_vsize_is_primary, emit_regtest_caveats
from experiments.registry import register


VAULT_AMOUNT = 49_999_900
WITHDRAW_STEP = 5_000_000  # sats per partial withdrawal
DEFAULT_MAX_ITERATIONS = 10


@register(
    name="revault_amplification",
    description="Partial withdrawal (revault) chaining and cost amplification",
    tags=["core", "capability_gap", "quantitative", "revault", "cost_analysis"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    max_iterations = getattr(adapter, "max_withdrawals", DEFAULT_MAX_ITERATIONS)

    result = ExperimentResult(
        experiment="revault_amplification",
        covenant=adapter.name,
        params={
            "vault_amount_sats": VAULT_AMOUNT,
            "withdraw_step_sats": WITHDRAW_STEP,
            "max_iterations": max_iterations,
        },
    )

    rpc = adapter.rpc
    from harness.metrics import TxMetrics

    try:
        result.observe(
            "PRIOR ART: CCV's partial withdrawal via trigger_and_revault is a "
            "core feature of BIP-443 [Ing23].  CTV's all-or-nothing unvault is "
            "inherent to BIP-119 [Rub20].  OP_VAULT supports partial withdrawal "
            "with automatic revault (BIP-345 [OS23]).  This experiment measures "
            "the cumulative cost of N sequential partial withdrawals."
        )

        if not adapter.supports_revault():
            result.observe(
                f"{adapter.name} does not support native revault.  "
                "Partial withdrawals require full unvault + new vault creation."
            )
            # Measure the full-cycle fallback cost (one full unvault + withdraw)
            vault = adapter.create_vault(VAULT_AMOUNT)
            result.observe(f"Created vault: {vault.vault_txid[:16]}… ({vault.amount_sats} sats)")

            unvault = adapter.trigger_unvault(vault)
            withdraw = adapter.complete_withdrawal(unvault)
            cycle_metrics = adapter.collect_tx_metrics(withdraw, rpc)
            single_cycle_vsize = cycle_metrics.vsize
            single_cycle_fee = cycle_metrics.fee_sats

            result.observe(
                f"Full unvault+withdraw cycle: vsize={single_cycle_vsize}, "
                f"fee={single_cycle_fee} sats"
            )
            result.observe(
                "For N partial withdrawals, CTV must do N full cycles "
                "(unvault everything + create new vault each time)."
            )

            # Record extrapolated per-step data for comparison table
            for i in range(1, max_iterations + 1):
                result.add_tx(TxMetrics(
                    label=f"revault_step_{i}",
                    vsize=single_cycle_vsize,
                    weight=cycle_metrics.weight,
                    fee_sats=single_cycle_fee,
                    num_inputs=cycle_metrics.num_inputs,
                    num_outputs=cycle_metrics.num_outputs,
                ))
                result.observe(
                    f"  Step {i} (CTV equivalent): cumulative_vsize="
                    f"{single_cycle_vsize * i}, cumulative_fee="
                    f"{single_cycle_fee * i} sats"
                )

            return result

        # CCV path: chain partial withdrawals, recording per-step metrics
        vault = adapter.create_vault(VAULT_AMOUNT)
        result.observe(f"Created vault: {vault.vault_txid[:16]}… ({vault.amount_sats} sats)")

        cumulative_fees = 0
        cumulative_vsize = 0
        iteration = 0

        while iteration < max_iterations and vault.amount_sats > WITHDRAW_STEP + 10_000:
            iteration += 1
            withdraw_amount = min(WITHDRAW_STEP, vault.amount_sats - 10_000)

            unvault_state, new_vault = adapter.trigger_revault(vault, withdraw_amount)

            # Complete the partial withdrawal
            rpc.mine(adapter.locktime if hasattr(adapter, 'locktime') else 10)
            withdraw_record = adapter.complete_withdrawal(unvault_state)
            metrics = adapter.collect_tx_metrics(withdraw_record, rpc)

            # Re-label with consistent sweep label
            metrics.label = f"revault_step_{iteration}"
            result.add_tx(metrics)

            if metrics.fee_sats:
                cumulative_fees += metrics.fee_sats
            cumulative_vsize += metrics.vsize

            result.observe(
                f"  Step {iteration}: withdrew {withdraw_amount} sats, "
                f"vsize={metrics.vsize}, fee={metrics.fee_sats} sats, "
                f"remainder={new_vault.amount_sats} sats "
                f"[cumulative: vsize={cumulative_vsize}, fee={cumulative_fees}]"
            )

            vault = new_vault

        result.observe(
            f"Completed {iteration} partial withdrawals.  "
            f"Final vault remainder: {vault.amount_sats} sats.  "
            f"Cumulative: vsize={cumulative_vsize}, fees={cumulative_fees} sats."
        )

    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")

    emit_regtest_caveats(
        result,
        experiment_specific=(
            "Revault chaining is a consensus property — CCV's trigger_and_revault "
            "clause (BIP-443 [Ing23]) and CTV's all-or-nothing unvault (BIP-119 "
            "[Rub20]) are identical on regtest and mainnet.  Per-step vsize is "
            "structurally constant (verified by watchtower_exhaustion experiment).  "
            "The cumulative cost model is valid; fee amounts are regtest artifacts."
        ),
    )
    return result
