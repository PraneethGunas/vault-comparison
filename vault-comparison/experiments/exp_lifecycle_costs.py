"""Experiment A: Vault Lifecycle Transaction Costs

Measures the on-chain cost of the complete vault lifecycle for each
covenant type: deposit → unvault → withdrawal.

This is the foundational comparison — every vault design must support
this basic flow, and the transaction sizes directly determine the
minimum cost of using the vault.

Metrics collected:
- vsize and weight of each transaction in the lifecycle
- Fee paid at each step
- Total lifecycle cost
- Script types used (bare CTV, P2WSH, P2TR, etc.)
- Number of inputs/outputs per step
"""

from adapters.base import VaultAdapter
from harness.metrics import ExperimentResult, TxMetrics
from harness.rpc import RegTestRPC
from harness.regtest_caveats import emit_vsize_is_primary
from experiments.registry import register


VAULT_AMOUNT = 49_999_900  # sats


@register(
    name="lifecycle_costs",
    description="Full vault lifecycle transaction sizes and fees",
    tags=["core", "comparative", "quantitative"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    result = ExperimentResult(
        experiment="lifecycle_costs",
        covenant=adapter.name,
        params={"vault_amount_sats": VAULT_AMOUNT},
    )

    rpc = adapter.rpc

    try:
        # Step 1: Create vault
        vault = adapter.create_vault(VAULT_AMOUNT)
        tovault_record = _make_record("tovault", vault.vault_txid, vault.amount_sats)
        tovault_metrics = adapter.collect_tx_metrics(tovault_record, rpc)
        result.add_tx(tovault_metrics)
        result.observe(f"Vault created: {vault.vault_txid[:16]}... ({vault.amount_sats} sats)")

        # Step 2: Trigger unvault
        unvault = adapter.trigger_unvault(vault)
        unvault_record = _make_record("unvault", unvault.unvault_txid, unvault.amount_sats)
        unvault_metrics = adapter.collect_tx_metrics(unvault_record, rpc)
        result.add_tx(unvault_metrics)
        result.observe(f"Unvault triggered: {unvault.unvault_txid[:16]}... (timelock: {unvault.blocks_remaining} blocks)")

        # Step 3: Complete withdrawal
        withdraw_record = adapter.complete_withdrawal(unvault)
        withdraw_metrics = adapter.collect_tx_metrics(withdraw_record, rpc)
        result.add_tx(withdraw_metrics)
        result.observe(f"Withdrawal complete: {withdraw_record.txid[:16]}... via {withdraw_record.label}")

        result.observe(f"Total lifecycle vsize: {result.total_vsize()} vbytes")
        result.observe(f"Total lifecycle fees: {result.total_fees()} sats")

    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")

    emit_vsize_is_primary(result)
    return result


def _make_record(label, txid, amount):
    from adapters.base import TxRecord
    return TxRecord(txid=txid, label=label, amount_sats=amount)
