"""Experiment: CAT+CSFS Cold Key Recovery — No-Covenant Recovery Path

Analyzes the security properties and attack surface of the CAT+CSFS
vault's recovery mechanism.  Unlike the trigger/withdraw paths that use
CSFS+CHECKSIG introspection, recovery uses a simple OP_CHECKSIG with the
cold key.  There is NO covenant enforcement on the recovery output.

=== ARCHITECTURE ===
Recovery leaf script: cold_pk_xonly OP_CHECKSIG

That's it.  No CAT, no CSFS, no amount checking, no output constraints.
The cold key can send the vault funds to ANY address.

This is by design: recovery is the escape hatch.  But it means cold key
compromise is catastrophic — the attacker can immediately sweep to any
address with no timelock, no watchtower defense, and no covenant
protection.

=== RELATED WORK ===
All four vault designs have single-point-of-failure cold/recovery keys:
  - CTV: Cold key controls tocold destination (pre-committed but
    cold key holder controls the destination wallet)
  - CCV: Recovery is KEYLESS — anyone can trigger, goes to pre-committed
    recovery address (controlled by recovery wallet)
  - OP_VAULT: Recovery requires recoveryauth key, goes to pre-committed
    recovery address.  Recovery address is encoded as a scriptPubKey
    hash in the OP_VAULT output — immutable.
  - CAT+CSFS: Recovery requires cold key, goes to cold wallet (P2WPKH).
    No destination constraint — cold key holder signs SIGHASH_DEFAULT
    which commits to the actual output, not an embedded one.

Poelstra's "CAT and Schnorr Tricks II" (https://blog.blockstream.com/
cat-and-schnorr-tricks-ii/) proposes an alternative CAT-only vault where
the cold key does NOT grant unconstrained sweeps.  Instead, the cold key
triggers a RECURSIVE RESET: funds return to the staging covenant with a
new target and a reset timelock.  Cold key compromise under that model
leads to an indefinite liveness battle (attacker resets, owner re-triggers,
attacker resets again) rather than immediate theft.  Phase 5 of this
experiment models the cost of that alternative design.

=== THREAT MODEL: Cold key compromise ===
Attacker: Has the cold key.  Goal: steal all vault funds immediately.
Severity: CRITICAL for all vault designs.
CAT+CSFS specific: The attacker broadcasts sign_recover() with a
  modified output (attacker address).  Since the recover leaf is just
  OP_CHECKSIG with SIGHASH_DEFAULT, the cold key holder controls where
  funds go.  Wait — actually, the VaultPlan computes the recovery output
  at construction time (cold wallet address).  But an attacker with the
  cold PRIVATE KEY can construct a completely new recovery transaction
  spending the vault UTXO to any address.

Key difference: CCV's recovery goes to a pre-committed address even
without a key.  OP_VAULT's recovery goes to a pre-committed address
(enforced by the opcode).  CAT+CSFS's recovery goes wherever the cold
key signs for — the vault script doesn't constrain the recovery output.

=== EMPIRICAL DEMONSTRATION ===
Phase 1: Normal recovery — verify the happy path.
Phase 2: Attacker recovery — construct a recovery tx that sends funds
  to an attacker-controlled address using the cold key.  Expected:
  ACCEPTED — the recover leaf is just OP_CHECKSIG.
Phase 3: Recovery timing analysis — measure the cold key's power:
  can recover from vault state (before trigger) and vault-loop state
  (after trigger).  No timelock on either.
Phase 4: Cross-vault recovery security comparison.
Phase 5: Poelstra-style reset-loop cost model — counterfactual analysis
  of what the recovery economics would look like under a recursive
  staging design (cold key resets instead of sweeping).
"""

import sys
from pathlib import Path

from adapters.base import VaultAdapter, VaultState, UnvaultState, TxRecord
from harness.metrics import ExperimentResult, TxMetrics
from harness.regtest_caveats import emit_regtest_caveats
from experiments.registry import register


VAULT_AMOUNT = 49_999_900


@register(
    name="cat_csfs_cold_key_recovery",
    description="CAT+CSFS cold key recovery: no-covenant recovery path and cold key compromise",
    tags=["cat_csfs_only", "security", "critical"],
    required_covenants=["cat_csfs"],
)
def run(adapter: VaultAdapter) -> ExperimentResult:
    result = ExperimentResult(
        experiment="cat_csfs_cold_key_recovery",
        covenant=adapter.name,
        params={"vault_amount_sats": VAULT_AMOUNT},
    )

    if adapter.name != "cat_csfs":
        result.observe("Skipping — CAT+CSFS-specific experiment.")
        return result

    try:
        _run_cold_key_recovery(adapter, result)
    except Exception as e:
        result.error = str(e)
        result.observe(f"FAILED: {e}")
        import traceback
        result.observe(traceback.format_exc())

    emit_regtest_caveats(
        result,
        experiment_specific=(
            "Recovery is a consensus-level operation — the OP_CHECKSIG "
            "validation in the recover leaf is identical on regtest and "
            "mainnet.  The cold key redirection test (Phase 2) demonstrates "
            "a real vulnerability: any holder of the cold private key can "
            "redirect vault funds.  This is inherent to the OP_CHECKSIG "
            "recovery design and not a regtest artifact."
        ),
    )

    return result


def _run_cold_key_recovery(adapter, result):
    """Run the cold key recovery analysis."""
    CAT_CSFS_REPO = Path(__file__).resolve().parents[2] / "simple-cat-csfs-vault"
    repo_str = str(CAT_CSFS_REPO)
    if repo_str not in sys.path:
        sys.path.insert(0, repo_str)

    from bitcoin.core import (
        CMutableTransaction, CTxIn, CTxOut, CTransaction,
        CTxInWitness, CScriptWitness, CTxWitness, COutPoint,
    )
    from bitcoin.core.script import CScript
    from vault import VaultPlan, Wallet, txid_to_bytes
    from taproot import (
        NUMS_POINT_X, LEAF_VERSION_TAPSCRIPT,
        build_control_block, tapleaf_hash,
        compute_tapscript_sighash, schnorr_sign,
    )

    cat_rpc = adapter._cat_rpc
    rpc = adapter.rpc

    # ── Phase 1: Normal recovery ──────────────────────────────────────
    result.observe("=" * 60)
    result.observe("PHASE 1: Normal recovery (happy path)")
    result.observe("=" * 60)

    vault = adapter.create_vault(VAULT_AMOUNT)
    plan = vault.extra["plan"]
    result.observe(f"Vault created: {vault.vault_txid[:16]}... ({vault.amount_sats} sats)")
    result.observe(f"Cold wallet: {adapter.cold_wallet.p2wpkh_address}")

    # Recovery from vault state
    recover_record = adapter.recover(vault)
    recover_info = rpc.get_tx_info(recover_record.txid)
    recover_vsize = recover_info["vsize"]
    result.observe(f"Recovery from vault: {recover_record.txid[:16]}... ({recover_vsize} vB)")

    # Verify funds went to cold wallet
    recover_output = recover_info["vout"][0]
    recover_addr = recover_output.get("scriptPubKey", {}).get("address", "")
    recover_amount = int(recover_output["value"] * 100_000_000)
    result.observe(f"Recovery output: {recover_amount} sats → {recover_addr}")

    if recover_addr == adapter.cold_wallet.p2wpkh_address:
        result.observe("CONFIRMED: Funds recovered to cold wallet.")
    else:
        result.observe(f"WARNING: Recovery went to unexpected address: {recover_addr}")

    result.add_tx(TxMetrics(
        label="normal_recovery_from_vault",
        txid=recover_record.txid,
        vsize=recover_vsize,
        weight=recover_info.get("weight", 0),
        amount_sats=recover_amount,
        script_type="p2tr_checksig",
    ))

    # Recovery from vault-loop state
    vault2 = adapter.create_vault(VAULT_AMOUNT)
    unvault2 = adapter.trigger_unvault(vault2)
    recover2 = adapter.recover(unvault2)
    recover2_info = rpc.get_tx_info(recover2.txid)
    recover2_vsize = recover2_info["vsize"]
    result.observe(f"Recovery from vault-loop: {recover2.txid[:16]}... ({recover2_vsize} vB)")

    result.add_tx(TxMetrics(
        label="normal_recovery_from_loop",
        txid=recover2.txid,
        vsize=recover2_vsize,
        weight=recover2_info.get("weight", 0),
        amount_sats=recover2.amount_sats,
        script_type="p2tr_checksig",
    ))

    # ── Phase 2: Attacker recovery (cold key redirects funds) ─────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 2: Cold key compromise — attacker redirects recovery")
    result.observe("=" * 60)

    vault3 = adapter.create_vault(VAULT_AMOUNT)
    plan3 = vault3.extra["plan"]
    result.observe(f"Vault created: {vault3.vault_txid[:16]}...")

    # Build a recovery tx that sends to an ATTACKER address
    attacker_wallet = Wallet.generate(b"cold-key-attacker")
    attacker_spk = attacker_wallet.p2wpkh_script_pubkey

    vault_txid_bytes = txid_to_bytes(vault3.vault_txid)
    source_amount = plan3.amount_at_step(1)
    recover_amount = source_amount - plan3.fees_per_step

    attacker_tx = CMutableTransaction()
    attacker_tx.nVersion = 2
    attacker_tx.vin = [CTxIn(COutPoint(vault_txid_bytes, 0), nSequence=0)]
    attacker_tx.vout = [CTxOut(recover_amount, CScript(attacker_spk))]

    # Sign with the cold key (which the attacker has)
    recover_script = plan3.vault_recover_script
    tl_hash = tapleaf_hash(recover_script)

    sighash = compute_tapscript_sighash(
        tx=CTransaction.from_tx(attacker_tx),
        input_index=0,
        prevouts=[(vault_txid_bytes, 0)],
        amounts=[source_amount],
        scriptpubkeys=[plan3.vault_spk],
        tapleaf_hash_val=tl_hash,
        hash_type=0x00,  # SIGHASH_DEFAULT — signs everything
    )

    sig = schnorr_sign(adapter.cold_wallet.secret, sighash)

    control_block = build_control_block(
        NUMS_POINT_X,
        LEAF_VERSION_TAPSCRIPT,
        plan3.vault_output_parity,
        [plan3.vault_trigger_hash],
    )

    witness_items = [
        sig,                    # for OP_CHECKSIG
        recover_script,         # tapscript
        control_block,          # control block
    ]

    attacker_tx.wit = CTxWitness([
        CTxInWitness(CScriptWitness(witness_items))
    ])

    attacker_hex = CTransaction.from_tx(attacker_tx).serialize().hex()

    result.observe(f"Attacker address: {attacker_wallet.p2wpkh_address}")
    result.observe("Broadcasting recovery to attacker address...")

    try:
        txid = cat_rpc.sendrawtransaction(attacker_hex)
        cat_rpc.generatetoaddress(1, adapter.fee_wallet.p2wpkh_address)

        tx_info = cat_rpc.getrawtransaction(txid, True)
        actual_addr = tx_info["vout"][0]["scriptPubKey"].get("address", "")
        theft_amount = int(tx_info["vout"][0]["value"] * 100_000_000)

        result.observe(f"ACCEPTED: {txid[:16]}...")
        result.observe(f"Funds redirected: {theft_amount} sats → {actual_addr}")

        if actual_addr == attacker_wallet.p2wpkh_address:
            result.observe(
                "CONFIRMED: Cold key holder can redirect recovery funds to "
                "ANY address.  The recover leaf (cold_pk OP_CHECKSIG) has "
                "NO covenant constraint on the output.  SIGHASH_DEFAULT "
                "commits to the actual output, so the cold key holder "
                "controls the destination."
            )
        else:
            result.observe(f"Output went to: {actual_addr} (expected attacker)")

        result.add_tx(TxMetrics(
            label="attacker_recovery",
            txid=txid,
            vsize=tx_info.get("vsize", 0),
            weight=tx_info.get("weight", 0),
            amount_sats=theft_amount,
            script_type="p2tr_checksig_redirected",
        ))

    except Exception as e:
        err_str = str(e)
        result.observe(f"REJECTED: {err_str[:200]}")
        result.observe(
            "UNEXPECTED: Cold key recovery with attacker output was rejected.  "
            "This contradicts the expected behavior of OP_CHECKSIG."
        )
        result.error = f"Cold key redirection rejected: {err_str[:100]}"

    # ── Phase 3: Recovery timing analysis ─────────────────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 3: Recovery timing — no timelock on recovery")
    result.observe("=" * 60)

    result.observe(
        "The recover leaf has NO OP_CHECKSEQUENCEVERIFY.  The cold key "
        "can sweep funds IMMEDIATELY from either vault or vault-loop state."
    )
    result.observe(
        "  Recovery from vault: No trigger needed.  Cold key directly "
        "spends the vault UTXO.  Fastest possible theft."
    )
    result.observe(
        "  Recovery from vault-loop: Cold key spends the vault-loop UTXO "
        "during the CSV delay.  Beats the hot key withdrawal."
    )
    result.observe(
        f"  Vault recovery vsize: {recover_vsize} vB"
    )
    result.observe(
        f"  Loop recovery vsize: {recover2_vsize} vB"
    )
    result.observe(
        "  Both are lightweight: simple OP_CHECKSIG witness (sig + script + "
        "control block).  No CSFS overhead, no preimage splitting."
    )

    # Timing analysis
    result.observe("")
    result.observe("DEFENSE ANALYSIS: What protects against cold key theft?")
    result.observe(
        "  NOTHING in the vault protocol.  Cold key compromise = immediate "
        "total fund loss.  No timelock, no watchtower, no recovery from "
        "recovery."
    )
    result.observe(
        "  External defenses only:"
    )
    result.observe(
        "    - Multisig cold key (requires protocol change or taproot MuSig)"
    )
    result.observe(
        "    - Hardware security module (HSM) for cold key"
    )
    result.observe(
        "    - Shamir's Secret Sharing for cold key backup"
    )
    result.observe(
        "    - Geographic distribution of cold key material"
    )

    # ── Phase 4: Cross-vault recovery comparison ──────────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 4: Recovery security comparison")
    result.observe("=" * 60)
    result.observe(
        "  CTV:      Recovery = tocold_tx (pre-committed CTV template).  "
        "Cold key holder controls the destination wallet, but the "
        "tocold transaction itself is CTV-locked to a specific output.  "
        "Cold key compromise: attacker controls destination wallet."
    )
    result.observe(
        "  CCV:      Recovery = KEYLESS (anyone can trigger).  Goes to "
        "pre-committed recovery address enforced by CCV.  "
        "No key compromise possible for recovery itself.  "
        "Recovery wallet compromise: attacker controls destination."
    )
    result.observe(
        "  OP_VAULT: Recovery = recoveryauth key + OP_VAULT_RECOVER.  "
        "Goes to pre-committed recovery address (SPK hash in output).  "
        "Recoveryauth key compromise: can grief (trigger recovery) but "
        "funds go to pre-committed address.  Recovery address is safe."
    )
    result.observe(
        "  CAT+CSFS: Recovery = cold key OP_CHECKSIG.  No output constraint.  "
        "Cold key compromise: IMMEDIATE TOTAL THEFT to any address.  "
        "No pre-committed recovery address.  No defense."
    )
    result.observe(
        "  RECOVERY SECURITY RANKING:"
    )
    result.observe(
        "    1. CCV (keyless recovery, pre-committed destination — "
        "no single key can redirect)"
    )
    result.observe(
        "    2. OP_VAULT (recoveryauth key, pre-committed destination — "
        "key compromise = grief, not theft)"
    )
    result.observe(
        "    3. CTV (CTV-locked tocold, destination wallet holds funds — "
        "wallet key compromise = theft of recovered funds)"
    )
    result.observe(
        "    4. CAT+CSFS (cold key OP_CHECKSIG, no destination constraint — "
        "cold key compromise = IMMEDIATE DIRECT THEFT)"
    )
    result.observe(
        "  DESIGN INSIGHT: The simplicity of the recover leaf (cold_pk "
        "OP_CHECKSIG) is both a strength and a weakness.  It's the simplest "
        "possible recovery mechanism — no complex script to audit, no "
        "risk of logic bugs.  But it offers NO protocol-level protection "
        "against cold key compromise.  The tradeoff: implementation "
        "simplicity vs recovery security depth."
    )

    # ── Phase 5: Poelstra-style reset-loop cost model ──────────────────
    result.observe("")
    result.observe("=" * 60)
    result.observe("PHASE 5: Poelstra-style recursive reset — counterfactual analysis")
    result.observe("=" * 60)
    result.observe(
        "Poelstra's 'CAT and Schnorr Tricks II' proposes an alternative "
        "recovery model for CAT-based vaults where the cold key does NOT "
        "grant an unconstrained sweep.  Instead, the cold key triggers a "
        "RECURSIVE RESET: funds return to the SAME staging covenant with "
        "a new target destination and a reset timelock."
    )
    result.observe(
        "Under that design, cold key compromise leads to a LIVENESS BATTLE, "
        "not immediate theft:"
    )
    result.observe(
        "  Round N: Owner triggers withdrawal → Attacker (cold key) resets "
        "staging → funds return to covenant with reset timelock → repeat."
    )
    result.observe(
        "The attacker CANNOT steal funds because the reset sends coins back "
        "to the same staging script (recursive covenant).  The attacker can "
        "only delay the owner indefinitely."
    )

    # Cost model using measured vsizes from this experiment and exp_fee_sensitivity
    #
    # Our vault's measured vsizes:
    #   trigger_vsize: 221 vB (from exp_fee_sensitivity / lifecycle measurements)
    #   recover_vsize: measured above in Phase 1
    #
    # We import the verified structural constant rather than hand-estimating.
    # If the import fails (e.g., running standalone), fall back to the known value.
    try:
        from experiments.exp_fee_sensitivity import CATCSFS_TRIGGER_VSIZE
        measured_trigger_vsize = CATCSFS_TRIGGER_VSIZE
    except ImportError:
        measured_trigger_vsize = 221  # verified constant from lifecycle measurements

    # Poelstra's reset would use a CAT+CSFS introspection script similar
    # to the trigger leaf (not the bare OP_CHECKSIG we have), so we
    # estimate the reset vsize as comparable to the trigger vsize.
    # This is a LOWER BOUND — Poelstra's design is CAT-only (no CSFS),
    # which may be slightly larger due to the G-as-pubkey Schnorr trick.
    # The +15 vB accounts for: cold key signature (32B Schnorr) is the same
    # size as the hot key signature already in the trigger, but the reset
    # script adds a recursive-covenant output check (~15 vB additional
    # script weight for the OP_CAT-assembled output commitment).  This is
    # an ESTIMATE with ~±10 vB uncertainty — Poelstra's exact script has
    # not been implemented.
    estimated_reset_vsize = measured_trigger_vsize + 15  # trigger + recursive covenant overhead
    our_recover_vsize = recover_vsize  # measured in Phase 1

    result.observe("")
    result.observe("COST MODEL COMPARISON: Our design vs Poelstra-style reset")
    result.observe(f"  Our recover vsize (bare OP_CHECKSIG): {our_recover_vsize} vB (measured, Phase 1)")
    result.observe(f"  Our trigger vsize (CAT+CSFS introspection): {measured_trigger_vsize} vB (measured, exp_fee_sensitivity)")
    result.observe(f"  Poelstra reset vsize (ESTIMATED, CAT introspection + cold key): ~{estimated_reset_vsize} vB (±10 vB)")
    result.observe(
        "  NOTE: The reset vsize is estimated as trigger + 15 vB for the "
        "recursive covenant output check.  Poelstra's exact script has not "
        "been implemented; the ±10 vB uncertainty bound reflects possible "
        "variation in the CAT-only (vs CAT+CSFS) witness encoding."
    )
    result.observe("")

    # Model N rounds of the liveness battle
    max_battle_rounds = 10
    result.observe(f"LIVENESS BATTLE: {max_battle_rounds}-round cost projection")
    result.observe(f"  Each round: owner pays trigger ({measured_trigger_vsize} vB, measured) + "
                   f"attacker pays reset (~{estimated_reset_vsize} vB, estimated ±10 vB)")
    result.observe("")

    for fee_rate in [1, 10, 50, 100]:
        result.observe(f"  At {fee_rate} sat/vB:")
        owner_per_round = measured_trigger_vsize * fee_rate
        attacker_per_round = estimated_reset_vsize * fee_rate
        for n in [1, 5, max_battle_rounds]:
            owner_total = owner_per_round * n
            attacker_total = attacker_per_round * n
            combined = owner_total + attacker_total
            vault_pct = combined / VAULT_AMOUNT * 100
            result.observe(
                f"    {n:>2} rounds: owner={owner_total:>8,} sats, "
                f"attacker={attacker_total:>8,} sats, "
                f"combined={combined:>8,} sats ({vault_pct:.3f}% of vault)"
            )
        result.observe("")

    result.observe("BATTLE TERMINATION CONDITIONS:")
    result.observe(
        "  1. Fee exhaustion: combined fees drain the vault value.  At 10 sat/vB, "
        f"a {VAULT_AMOUNT:,}-sat vault survives ~{VAULT_AMOUNT // ((measured_trigger_vsize + estimated_reset_vsize) * 10):,} rounds."
    )
    result.observe(
        "  2. Attacker abandonment: attacker gives up (no financial gain, "
        "only denial of service).  Same rationality constraint as CCV griefing."
    )
    result.observe(
        "  3. Owner key rotation: owner sets up a new vault with a fresh "
        "cold key.  Requires out-of-band coordination (new key generation, "
        "new vault creation) while the battle continues on the old vault."
    )

    result.observe("")
    result.observe("COMPARISON: Our design vs Poelstra-style recovery")
    result.observe(
        "  Our design (bare OP_CHECKSIG):"
    )
    result.observe(
        "    Cold key compromise consequence: IMMEDIATE TOTAL THEFT"
    )
    result.observe(
        "    Recovery vsize: {v} vB (lightweight)".format(v=our_recover_vsize)
    )
    result.observe(
        "    Advantage: Simplest possible script, smallest witness"
    )
    result.observe(
        "    Disadvantage: No protocol-level defense against cold key theft"
    )
    result.observe(
        "  Poelstra-style recursive reset:"
    )
    result.observe(
        "    Cold key compromise consequence: LIVENESS DENIAL ONLY (no theft)"
    )
    result.observe(
        "    Reset vsize: ~{v} vB (heavier — requires introspection)".format(v=estimated_reset_vsize)
    )
    result.observe(
        "    Advantage: Cold key compromise is survivable — funds are never lost, "
        "only delayed.  Matches CCV/OP_VAULT security properties."
    )
    result.observe(
        "    Disadvantage: Requires recursive covenant (coins return to same "
        "script), larger witness, and the liveness battle has real fee costs"
    )
    result.observe(
        "    Implementation note: Poelstra's design achieves this with CAT alone "
        "(no CSFS) using a Schnorr discrete-log trick (G as pubkey), but the "
        "same could be built more cleanly with CAT+CSFS using the dual-verification "
        "pattern already used in our trigger/withdraw leaves."
    )
    result.observe("")
    result.observe(
        "VERDICT: The Poelstra-style reset would upgrade CAT+CSFS recovery "
        "from rank #4 (immediate theft) to rank #2 (liveness denial, matching "
        "OP_VAULT).  The cost is a ~{d} vB increase per recovery and the "
        "requirement for recursive covenants.  Whether this tradeoff is worth "
        "it depends on the custody threat model: for high-value vaults where "
        "cold key compromise is a realistic threat, the Poelstra model is "
        "strictly superior.  For simpler setups where the cold key is in a "
        "hardware wallet or Shamir-split, the bare OP_CHECKSIG may be "
        "adequate.".format(d=estimated_reset_vsize - our_recover_vsize)
    )
