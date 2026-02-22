"""Experiment H: CCV-Specific Edge Cases and Developer Footguns

Tests three CCV-specific edge cases classified as developer footguns
and misconfiguration risks, not protocol-level attack vectors.

=== RELATED WORK ===
The OP_SUCCESS semantics for undefined CCV flags are a deliberate
consensus design choice for forward compatibility, specified in BIP-443
(https://bips.dev/443/).  Mode confusion risk is discussed by Ingala
in the MATT design discussions on bitcoin-dev
(https://gnusha.org/pi/bitcoindev/CAMhCMoFYF+9NL1sqKfn=ma3C_mfQv7mj2fqbqO5WXVwd6vyhLw@mail.gmail.com/).
Keypath bypass risk is inherent to Taproot (BIP-341) and applies
equally to Lightning, DLCs, and any P2TR contract.  This experiment
constructs P2TR outputs with undefined CCV flag bytes (4, 7, 128, 255),
funds them on regtest, and confirms that spends succeed unconditionally
via OP_SUCCESS, directing funds to arbitrary addresses.

=== THREAT MODEL 1: Mode confusion (CCV_FLAG values) ===
Attacker: None (developer error).  An undefined CCV_FLAG value (e.g., 4,
  128, 255) causes OP_SUCCESS behavior — script succeeds unconditionally.
Goal: N/A — not an adversarial attack.
Impact if deployed: Anyone can spend the output (zero covenant enforcement).
  Severity: Critical if deployed, but catchable by static analysis.
Rationality: Not applicable — this is a tooling/documentation problem.
Classification: CCV-specific developer footgun.

=== THREAT MODEL 2: Keypath bypass (Taproot misconfiguration) ===
Attacker: Has the private key corresponding to the Taproot internal key.
  This only exists if developer passed a real pubkey as `alternate_pk`.
Goal: Spend vault output via keypath, bypassing all CCV enforcement.
Cost: One keypath spend (~57 vbytes witness).  Trivial.
Payoff: Full vault balance.
Rationality: If the misconfiguration exists, always rational.  But the
  misconfiguration itself is the vulnerability — pymatt default
  (alternate_pk=None, NUMS point) makes this impossible.
Classification: Taproot security hygiene, not CCV-specific.  Applies
  equally to Lightning, DLCs, any Taproot contract.

=== THREAT MODEL 3: Sentinel value confusion (-1 vs 0) ===
Attacker: None (developer error during custom contract authoring).
Impact: Clause skips a critical check (-1 used instead of 0) or fails
  unexpectedly (0 used instead of -1).
Rationality: N/A — documentation/API footgun.
Classification: Mitigated by typed APIs and named constants in pymatt.

A conference reviewer would note that findings 2 and 3 apply to general
Taproot contract development, not CCV specifically.  Only finding 1
(OP_SUCCESS for undefined modes) is CCV-specific.

=== TM8 ESCALATION ===
This experiment tests mode confusion on minimal synthetic contracts.
The escalation to production-shaped Vault taptrees is in
exp_ccv_mode_bypass.py, which demonstrates the CCVWildSpend transition
(vault UTXO → complete covenant bypass → funds to attacker address).
See exp_ccv_mode_bypass for the critical-severity finding (TM8).
"""

import sys
from pathlib import Path

from adapters.base import VaultAdapter
from harness.metrics import ExperimentResult, TxMetrics
from harness.regtest_caveats import emit_regtest_caveats
from experiments.registry import register


@register(
    name="ccv_edge_cases",
    description="CCV-specific edge cases: mode confusion, keypath bypass, sentinel values",
    tags=["ccv_only", "developer_footguns", "security"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    result = ExperimentResult(
        experiment="ccv_edge_cases",
        covenant=adapter.name,
        params={},
    )

    if adapter.name != "ccv":
        result.observe(
            f"Skipping CCV edge-case tests on {adapter.name} — "
            "these are CCV/Taproot-specific."
        )
        return result

    try:
        _test_mode_confusion(adapter, result)
        _test_keypath_bypass_analysis(adapter, result)
        _test_sentinel_value_analysis(adapter, result)
    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")

    # ── Regtest limitations ──────────────────────────────────────────
    emit_regtest_caveats(
        result,
        experiment_specific=(
            "The mode confusion test is FULLY VALID on regtest — OP_SUCCESS "
            "semantics are consensus behavior, not relay policy.  If an "
            "undefined CCV flag triggers OP_SUCCESS on regtest, it will do "
            "the same on mainnet.  This is one experiment where regtest "
            "faithfully reproduces mainnet behavior because the finding "
            "is about script execution semantics, not economic dynamics."
        ),
    )

    return result


def _ensure_pymatt_imports():
    """Lazy-load pymatt modules needed for raw Tapscript construction."""
    PYMATT_REPO = Path(__file__).resolve().parents[2] / "pymatt"
    paths = [str(PYMATT_REPO / "src"), str(PYMATT_REPO / "examples" / "vault")]
    for p in paths:
        if p not in sys.path:
            sys.path.insert(0, p)

    from matt.argtypes import IntType
    from matt.btctools import key
    from matt.btctools.messages import CTxOut
    from matt.btctools.script import CScript, OP_CHECKCONTRACTVERIFY, OP_SWAP, OP_TRUE
    from matt.contracts import ClauseOutput, OpaqueP2TR, StandardAugmentedP2TR, StandardClause
    from matt.utils import addr_to_script

    return {
        "IntType": IntType,
        "key": key,
        "CTxOut": CTxOut,
        "CScript": CScript,
        "OP_CHECKCONTRACTVERIFY": OP_CHECKCONTRACTVERIFY,
        "OP_SWAP": OP_SWAP,
        "OP_TRUE": OP_TRUE,
        "ClauseOutput": ClauseOutput,
        "OpaqueP2TR": OpaqueP2TR,
        "StandardAugmentedP2TR": StandardAugmentedP2TR,
        "StandardClause": StandardClause,
        "addr_to_script": addr_to_script,
    }


def _make_mode_contract(mods, mode: int, internal_pk: bytes, recover_pk: bytes):
    """Build a minimal P2TR contract with a single CCV clause using the given mode.

    The sweep clause pushes: 0, <output_index>, <recover_pk>, 0, <mode>, OP_CCV, OP_TRUE.
    For defined modes (0, 1, 2, 3), CCV enforces covenant rules — a mutated
    spend (different output script) will be rejected.
    For undefined modes (4, 7, 128, 255), CCV triggers OP_SUCCESS — the entire
    script succeeds unconditionally, so the mutated spend is accepted.
    """
    CScript = mods["CScript"]
    OP_SWAP = mods["OP_SWAP"]
    OP_CCV = mods["OP_CHECKCONTRACTVERIFY"]
    OP_TRUE = mods["OP_TRUE"]
    ClauseOutput = mods["ClauseOutput"]
    OpaqueP2TR = mods["OpaqueP2TR"]
    StandardAugmentedP2TR = mods["StandardAugmentedP2TR"]
    StandardClause = mods["StandardClause"]
    IntType = mods["IntType"]

    sweep = StandardClause(
        name="sweep",
        script=CScript([
            0,              # data (empty)
            OP_SWAP,        # put out_i on top
            recover_pk,     # expected output pubkey
            0,              # input index (-1 = skip, 0 = check)
            mode,           # THE FLAG VALUE UNDER TEST
            OP_CCV,
            OP_TRUE,
        ]),
        arg_specs=[("out_i", IntType())],
        next_outputs_fn=lambda args, _: [
            ClauseOutput(n=args["out_i"], next_contract=OpaqueP2TR(recover_pk))
        ],
    )

    # Create a concrete subclass for this specific mode value
    contract = type(
        f"ModeContract_{mode}",
        (StandardAugmentedP2TR,),
        {"State": None},
    )(internal_pk, sweep)

    return contract


AMOUNT_SATS = 150_000
FEE_SATS = 1_000

# Mode values to test, with expected behavior per BIP-443:
# Defined flags: 0 (default), 1 (CHECK_INPUT), 2 (DEDUCT_OUTPUT_AMOUNT),
#   3 (CHECK_INPUT | DEDUCT_OUTPUT_AMOUNT — both flags composed)
# Undefined flags: 4, 7, 128, 255 — trigger OP_SUCCESS (forward-compat)
TEST_MODES = [
    (0,   "defined",   "default (check output, preserve amount)"),
    (1,   "defined",   "CCV_FLAG_CHECK_INPUT"),
    (2,   "defined",   "CCV_FLAG_DEDUCT_OUTPUT_AMOUNT"),
    (3,   "defined",   "CHECK_INPUT | DEDUCT_OUTPUT_AMOUNT"),
    (4,   "undefined", "bit 2 — no assigned meaning"),
    (7,   "undefined", "bits 0|1|2 — partially overlaps defined"),
    (128, "undefined", "bit 7 — high bit"),
    (255, "undefined", "all bits set"),
]


def _test_mode_confusion(adapter, result):
    """Empirically test CCV behavior with defined and undefined mode/flag values.

    For each mode value in TEST_MODES:
      1. Construct a raw Tapscript leaf with OP_CHECKCONTRACTVERIFY using that mode
      2. Fund it into a P2TR output on regtest
      3. Build a mutated spend tx that redirects funds to an attacker address
      4. Attempt to broadcast
      5. Record whether the spend was accepted (OP_SUCCESS) or rejected (covenant enforced)

    Expected: defined modes (0-3) reject the mutated spend; undefined modes (4+)
    accept it unconditionally via OP_SUCCESS semantics.
    """
    result.observe("=== Edge Case 1: CCV Mode/Flag Confusion (Empirical) ===")
    result.observe(
        "Testing OP_CHECKCONTRACTVERIFY with defined and undefined flag values. "
        "For each mode, we fund a P2TR output containing a CCV clause with that "
        "mode, then attempt a mutated spend redirecting funds to an attacker address."
    )

    mods = _ensure_pymatt_imports()
    manager = adapter._manager
    rpc = adapter._pymatt_rpc

    # Generate key material for the test contracts
    key_mod = mods["key"]
    internal_key = key_mod.ECKey()
    internal_key.generate(compressed=True)
    internal_pk = internal_key.get_pubkey().get_bytes()[1:]  # x-only

    recover_key = key_mod.ECKey()
    recover_key.generate(compressed=True)
    recover_pk = recover_key.get_pubkey().get_bytes()[1:]

    CTxOut = mods["CTxOut"]
    addr_to_script = mods["addr_to_script"]

    defined_accepted = 0
    defined_rejected = 0
    undefined_accepted = 0
    undefined_rejected = 0

    for mode_val, expected_class, description in TEST_MODES:
        result.observe(f"\n--- Mode {mode_val} ({expected_class}): {description} ---")

        try:
            # Step 1: Build the contract with this mode value
            contract = _make_mode_contract(mods, mode_val, internal_pk, recover_pk)

            # Step 2: Fund it into a P2TR output
            instance = manager.fund_instance(contract, AMOUNT_SATS)
            result.observe(f"  Funded P2TR output: {AMOUNT_SATS} sats")

            # Step 3: Build a legitimate spend tx, then mutate the output
            spend_tx, _ = manager.get_spend_tx(
                (instance, "sweep", {"out_i": 0})
            )
            spend_tx.wit.vtxinwit = [
                manager.get_spend_wit(instance, "sweep", {"out_i": 0})
            ]

            # MUTATION: redirect output to an attacker-controlled address
            attacker_addr = rpc.getnewaddress(f"mode-{mode_val}-attacker")
            spend_tx.vout[0] = CTxOut(
                AMOUNT_SATS - FEE_SATS,
                addr_to_script(attacker_addr),
            )

            # Step 4: Attempt to broadcast the mutated spend
            spend_hex = spend_tx.serialize().hex()
            try:
                txid = rpc.sendrawtransaction(spend_hex)
                # Mine it to confirm
                mine_addr = rpc.getnewaddress()
                rpc.generatetoaddress(1, mine_addr)

                # Verify the output went to the attacker
                tx_info = rpc.getrawtransaction(txid, True)
                actual_addr = tx_info["vout"][0]["scriptPubKey"].get("address", "")
                theft_confirmed = (actual_addr == attacker_addr)

                result.observe(
                    f"  ACCEPTED — mutated spend broadcast successfully (txid: {txid[:16]}...)"
                )
                if theft_confirmed:
                    result.observe(
                        f"  THEFT CONFIRMED: funds sent to attacker address"
                    )
                result.observe(f"  vsize: {tx_info.get('vsize', 'N/A')}, weight: {tx_info.get('weight', 'N/A')}")

                # Record metrics for accepted spends
                metrics = TxMetrics(
                    label=f"mode_{mode_val}_{expected_class}_accepted",
                    txid=txid,
                    vsize=tx_info.get("vsize", 0),
                    weight=tx_info.get("weight", 0),
                    amount_sats=AMOUNT_SATS - FEE_SATS,
                    num_inputs=len(tx_info.get("vin", [])),
                    num_outputs=len(tx_info.get("vout", [])),
                    script_type="p2tr_ccv_mode_test",
                )
                result.add_tx(metrics)

                if expected_class == "defined":
                    defined_accepted += 1
                    result.observe(
                        f"  UNEXPECTED: defined mode {mode_val} accepted mutated spend!"
                    )
                else:
                    undefined_accepted += 1
                    result.observe(
                        f"  EXPECTED: undefined mode triggers OP_SUCCESS, covenant bypassed"
                    )

            except Exception as rpc_err:
                err_msg = str(rpc_err)
                result.observe(f"  REJECTED — {err_msg[:120]}")

                if expected_class == "defined":
                    defined_rejected += 1
                    result.observe(
                        f"  EXPECTED: defined mode {mode_val} enforces covenant rules"
                    )
                else:
                    undefined_rejected += 1
                    result.observe(
                        f"  UNEXPECTED: undefined mode {mode_val} rejected (expected OP_SUCCESS)"
                    )

        except Exception as e:
            result.observe(f"  ERROR constructing/funding mode {mode_val}: {e}")

    # ── Summary ───────────────────────────────────────────────────────
    result.observe("\n=== Mode Confusion Summary ===")
    result.observe(f"Defined modes (0-3):   {defined_rejected} rejected, {defined_accepted} accepted")
    result.observe(f"Undefined modes (4+):  {undefined_accepted} accepted, {undefined_rejected} rejected")

    total_defined = defined_rejected + defined_accepted
    total_undefined = undefined_accepted + undefined_rejected

    if total_defined > 0 and defined_rejected == total_defined:
        result.observe("PASS: All defined modes correctly enforce covenant rules")
    elif defined_accepted > 0:
        result.observe(
            f"ANOMALY: {defined_accepted} defined mode(s) accepted mutated spends — "
            "investigate CCV implementation"
        )

    if total_undefined > 0 and undefined_accepted == total_undefined:
        result.observe(
            "PASS: All undefined modes trigger OP_SUCCESS — confirms forward-compat "
            "semantics and the developer footgun risk"
        )
    elif undefined_rejected > 0:
        result.observe(
            f"ANOMALY: {undefined_rejected} undefined mode(s) rejected — OP_SUCCESS "
            "may not apply to all undefined flags in this implementation"
        )

    result.observe(
        "\nIMPLICATION: A developer who accidentally uses an undefined CCV flag "
        "value creates an output with ZERO covenant enforcement. Anyone can spend "
        "it to any destination. This is by design (forward compatibility for future "
        "soft forks), but creates a silent, critical failure mode that static "
        "analysis tools must flag."
    )

    result.observe(
        "DESIGN TRADEOFF: OP_SUCCESS for undefined modes enables clean soft-fork "
        "upgrades (new flag meanings can be added without hard forks). The alternative "
        "— OP_FAIL for undefined modes — would be safer against developer error but "
        "would require hard forks to extend the flag space."
    )


def _test_keypath_bypass_analysis(adapter, result):
    """Analyze the Taproot keypath bypass risk.

    CCV vaults use P2TR outputs.  If the internal key has a known private
    key, keypath spending bypasses all script-path conditions.  The pymatt
    vault uses `alternate_pk=None`, which sets the internal key to a NUMS
    point (provably unspendable via keypath).

    This is NOT a CCV vulnerability — it's standard Taproot security hygiene
    that applies to ANY Taproot-based contract.
    """
    result.observe("=== Edge Case 2: Taproot Keypath Bypass (Misconfiguration) ===")

    # Check what the vault contract uses as its internal key
    vault_contract = adapter.vault_contract
    result.observe(
        f"Vault contract alternate_pk parameter: "
        f"{getattr(vault_contract, '_alternate_pk', 'None (NUMS point)')}"
    )

    result.observe(
        "The pymatt vault constructor's first parameter is `alternate_pk`.  "
        "When set to None, the internal Taproot key is a NUMS (Nothing Up My "
        "Sleeve) point — provably unspendable, so keypath spending is impossible.  "
        "All spending must go through script paths (trigger, trigger_and_revault, "
        "recover), which are CCV-enforced."
    )

    result.observe(
        "MISCONFIGURATION RISK: If a developer passes a real public key as "
        "`alternate_pk`, anyone with the corresponding private key can spend "
        "the vault output via Taproot keypath, bypassing ALL covenant "
        "enforcement (CCV checks, timelocks, recovery).  This is equivalent "
        "to putting a master override on a bank vault."
    )

    result.observe(
        "CLASSIFICATION: This is a Taproot misconfiguration, not a CCV "
        "protocol vulnerability.  The same risk applies to any Taproot "
        "contract (Lightning, DLCs, multisig).  A reviewer would note: "
        "'This tells us about Taproot security hygiene, not about covenants "
        "specifically.'  We include it for completeness but do not classify "
        "it as a CCV attack surface."
    )

    result.observe(
        "SEVERITY: Critical IF misconfigured, but N/A under correct usage.  "
        "The pymatt default (alternate_pk=None) is safe."
    )


def _test_sentinel_value_analysis(adapter, result):
    """Analyze the -1 vs 0 sentinel confusion risk.

    CCV uses -1 as a sentinel for 'don't check this output/input index.'
    Confusing -1 (skip) with 0 (check index 0) can produce scripts that
    either skip critical covenant checks or check the wrong output.

    This is a documentation/API design issue, not a protocol vulnerability.
    """
    result.observe("=== Edge Case 3: Sentinel Value Confusion (-1 vs 0) ===")

    result.observe(
        "CCV opcodes use integer parameters for output/input indices.  "
        "The value -1 is a sentinel meaning 'skip this check' (no output "
        "verification for this parameter).  Index 0 means 'check the first "
        "output.'  These are adjacent values with radically different "
        "semantics."
    )

    result.observe(
        "DEVELOPER FOOTGUN: In the vault contract, the `recover` clause "
        "uses specific output indices to verify the recovery output.  If a "
        "developer writing a custom clause confuses -1 (skip) with 0 "
        "(check first output), they create either: "
        "(a) a clause that skips a critical amount/script check (if they "
        "used -1 when they meant 0), or "
        "(b) a clause that fails unexpectedly (if they used 0 when they "
        "meant -1, and output 0 doesn't match expectations)."
    )

    result.observe(
        "COMPARISON WITH CTV: CTV has no equivalent sentinel — template "
        "hashes commit to the entire transaction, so there's no per-field "
        "opt-out.  The sentinel design is a consequence of CCV's granular "
        "output checking, which is more flexible but introduces this "
        "confusion risk."
    )

    result.observe(
        "CLASSIFICATION: Developer footgun, not a protocol vulnerability.  "
        "The -1/0 confusion would only affect custom contract development, "
        "not users of a correctly-implemented vault.  Analogous to confusing "
        "NULL with 0 in C — a well-known class of bugs, not a language flaw."
    )

    result.observe(
        "SEVERITY: Low (developer footgun).  Mitigated by type-safe APIs, "
        "documentation, and static analysis.  The pymatt vault contracts "
        "use named constants, reducing this risk."
    )
