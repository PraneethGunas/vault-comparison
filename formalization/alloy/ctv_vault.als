/**
 * ctv_vault.als — CTV (BIP-119) Vault Model
 *
 * State machine:
 *   VAULTED -> UNVAULTED -> {WITHDRAWN, RECOVERED}
 *
 * CTV semantics:
 *   - Commits to: nVersion, nLockTime, nSequence, output count,
 *     all output amounts+scripts, spend_index
 *   - Does NOT commit to: input prevouts, input amounts, witness data
 *   - This non-commitment to inputs is the root of address-reuse vulnerability
 *
 * Key requirements:
 *   - VAULTED -> UNVAULTED: NO signature (CTV template match only)
 *   - UNVAULTED -> WITHDRAWN: hot_key + CSV delay
 *   - UNVAULTED -> RECOVERED: CTV template only (no signature, immediate)
 *
 * No revault, no batching, no keyless recovery (recovery is CTV-locked,
 * not key-locked, but the template is fixed at vault creation).
 */
module ctv_vault

open btc_base
open vault_base
open threat_model

-- CTVTemplate is defined in vault_base.als (shared across all three vaults)
-- CTV commits to exact outputs (amounts + scripts)
-- CTV does NOT commit to input identity or amount
-- This is modeled by the absence of input constraints in CTVTrigger

-- ============================================================
-- CTV-specific vault UTXO subtypes
-- ============================================================

-- A vaulted UTXO locked by <H(unvault_template)> OP_CTV
sig CTVVaultedUTXO extends VaultUTXO {
  unvaultTemplate : one CTVTemplate  -- the template for the unvault tx
} {
  status = VAULTED
}

-- The unvaulted UTXO: P2WSH with IF (CSV+sig) / ELSE (CTV cold sweep)
sig CTVUnvaultedUTXO extends VaultUTXO {
  hotKey          : one Key,          -- hot key for withdrawal path
  coldTemplate    : one CTVTemplate,  -- CTV template for cold sweep
  anchorOutput    : lone UTXO         -- the 550-sat CPFP anchor (vout[1])
} {
  status = UNVAULTING
  hotKey = HotKey
}

sig CTVWithdrawnUTXO extends VaultUTXO {} {
  status = WITHDRAWN
}

sig CTVRecoveredUTXO extends VaultUTXO {} {
  status = RECOVERED
}

-- ============================================================
-- CTV Vault Family
-- ============================================================
sig CTVVaultFamily extends VaultFamily {
  hotKey  : one Key,
  coldKey : one Key,
  feeKey  : one Key
} {
  hotKey = HotKey
  coldKey = ColdKey
  feeKey = FeeKey
  -- Hot address is owned by hot key
  hotAddr.owner = HotKey
  -- Cold address is owned by cold key
  coldAddr.owner = ColdKey
}

-- ============================================================
-- CTV Transitions
-- ============================================================

-- Trigger: VAULTED -> UNVAULTED
-- NO signature required — anyone who knows the template can trigger
sig CTVTrigger extends TriggerTransition {
  template : one CTVTemplate
} {
  src in CTVVaultedUTXO
  -- The template determines outputs — check match
  template = (src :> CTVVaultedUTXO).unvaultTemplate
  -- CTV enforces output structure but NOT input identity
  -- This means: the tx outputs must match the template
  all d : dst | d in template.committedOutputs

  -- CRITICAL: No signature required for trigger
  -- This is modeled by NOT requiring any key in txn.signers
  -- (though signers may be non-empty for other inputs)
}

-- Withdrawal: UNVAULTED -> WITHDRAWN (hot path)
-- Requires: hot_key signature + CSV expiry
sig CTVWithdraw extends WithdrawTransition {} {
  src in CTVUnvaultedUTXO
  all d : dst | d in CTVWithdrawnUTXO
  -- Requires hot key signature
  HotKey in txn.signers
  -- CSV enforced by parent class
  -- Destination is the hot address
  all d : dst | d.script = family.hotAddr
}

-- Recovery: UNVAULTED -> RECOVERED (cold path)
-- CTV template only — no signature, immediate (no CSV)
sig CTVRecover extends RecoverTransition {} {
  src in CTVUnvaultedUTXO
  all d : dst | d in CTVRecoveredUTXO
  -- CTV-locked: template match suffices, no signature needed
  -- No CSV delay for recovery
  -- Destination is cold address (enforced by parent RecoverTransition)
}

-- ============================================================
-- CTV-specific fact: No revault capability
-- ============================================================
fact ctvNoRevault {
  no RevaultTransition & Transition  -- no revault transitions exist for CTV
  // More precisely: there are no RevaultTransition atoms
  // whose family is a CTVVaultFamily
  all r : RevaultTransition | r.family not in CTVVaultFamily
}

-- ============================================================
-- CTV-specific fact: Trigger requires no authorization
-- ============================================================
-- Anyone can trigger the unvault. This is structural to CTV.
fact ctvTriggerNoAuth {
  -- The trigger transaction needs no specific signer for the vault input.
  -- This is modeled by the ABSENCE of a signer constraint in CTVTrigger's
  -- sig facts (contrast with CCVTrigger which requires UnvaultKey in signers).
  -- No explicit constraint needed here — the lack of constraint IS the model.
}

-- ============================================================
-- CTV closing axioms: tie UTXO subtypes to transition types
-- ============================================================
fact ctvClosingAxioms {
  -- Every CTVWithdrawnUTXO must be produced by exactly one CTVWithdraw
  all u : CTVWithdrawnUTXO | one w : CTVWithdraw | u in w.dst

  -- Every CTVRecoveredUTXO must be produced by exactly one CTVRecover
  all u : CTVRecoveredUTXO | one r : CTVRecover | u in r.dst

  -- Every CTVUnvaultedUTXO must be produced by exactly one CTVTrigger
  all u : CTVUnvaultedUTXO | one t : CTVTrigger | u in t.dst
}

-- ============================================================
-- CTV transition cardinality: each transition produces exactly one typed output
-- (Fix R2-2: prevents solver from creating multi-output triggers/withdrawals)
-- ============================================================
fact ctvTransitionCardinality {
  -- CTV trigger produces exactly one unvaulted UTXO (no batching in CTV)
  all t : CTVTrigger | one (t.dst & CTVUnvaultedUTXO) and #t.dst = 1

  -- CTV withdrawal produces exactly one withdrawn UTXO
  all w : CTVWithdraw | one (w.dst & CTVWithdrawnUTXO) and #w.dst = 1

  -- CTV recovery produces exactly one recovered UTXO
  all r : CTVRecover | one (r.dst & CTVRecoveredUTXO) and #r.dst = 1
}

-- ============================================================
-- CTV family well-formedness: allUTXOs contains only CTV-typed UTXOs
-- ============================================================
fact ctvFamilyWellFormedness {
  -- A CTVVaultFamily's allUTXOs only contains CTV-subtyped VaultUTXOs
  all f : CTVVaultFamily |
    f.allUTXOs in (CTVVaultedUTXO + CTVUnvaultedUTXO + CTVWithdrawnUTXO + CTVRecoveredUTXO)

  -- All CTV-subtyped UTXOs belong to a CTVVaultFamily
  all u : (CTVVaultedUTXO + CTVUnvaultedUTXO + CTVWithdrawnUTXO + CTVRecoveredUTXO) |
    u.vaultFamily in CTVVaultFamily
}

-- ============================================================
-- ADDRESS REUSE VULNERABILITY MODEL
-- ============================================================
-- CTV commits to exact output amounts derived from the deposit.
-- If two deposits of different amounts go to the same CTV address,
-- the second deposit creates a UTXO whose value doesn't match the
-- template — it's either permanently stuck or overpays miners.

-- Model address reuse: two VaultUTXOs with the same script (address)
-- but different values
pred addressReuse[f1, f2: CTVVaultFamily] {
  f1 != f2
  f1.deposit.script = f2.deposit.script   -- same address
  f1.deposit.value != f2.deposit.value     -- different amounts
}

-- The reused deposit cannot be spent via its template
-- (template expects original amount, but UTXO has different amount)
pred stuckFunds[u: CTVVaultedUTXO] {
  -- The template commits to specific output values
  -- If the UTXO value doesn't match what the template expects as input,
  -- the outputs won't sum correctly
  some f : CTVVaultFamily | u in f.allUTXOs and
    u.value != f.depositValue
}

-- ============================================================
-- PROPERTY CHECKS: CTV-specific
-- ============================================================

-- Property 2 (CTV): Unauthorized extraction
-- With no keys, attacker cannot reach WITHDRAWN at AttackerAddr
assert ctvNoUnauthorizedExtraction_NoKey {
  noKeyAttacker implies
    no u : CTVWithdrawnUTXO | u.script = AttackerAddr
}

-- With hot key only, attacker CAN withdraw (to hot address, which
-- is the legitimate destination — but if attacker controls hot key,
-- the hot address IS the attacker's address in our threat model)
-- This should find a counterexample: hot key holder can withdraw.
assert ctvNoExtraction_HotKeyOnly {
  ctvHotKeyOnly implies
    no u : CTVWithdrawnUTXO | u.script = AttackerAddr
}

-- Property 5: CSV enforcement on withdrawal
assert ctvCSVEnforced {
  all w : CTVWithdraw |
    csvSatisfied[w.src, w.txn, w.src.csvDelay]
}

-- Property 6: Eventual withdrawal (LIVENESS)
-- Every vault should be withdrawable. Known violation: address reuse.
-- We assert this and expect Alloy to find the counterexample.
assert ctvEventualWithdrawal {
  all f : CTVVaultFamily |
    canWithdraw[f]
}

-- Property 7: Recovery always possible
-- CTV recovery is CTV-locked (template only), so it should always
-- be possible from UNVAULTED state. This should HOLD.
assert ctvRecoveryAlwaysPossible {
  all f : CTVVaultFamily |
    all u : f.allUTXOs |
      (u.status = UNVAULTING and live[u]) implies
        some r : CTVRecover | r.src = u
}

-- Property 8: No griefing loop
-- CTV has no revault, so state proliferation is impossible.
-- The worst griefing is hot-key attacker forcing cold sweep.
assert ctvNoStateProliferation {
  all f : CTVVaultFamily |
    #f.allUTXOs <= 3  -- deposit + unvaulted + (withdrawn or recovered)
}

-- ============================================================
-- Checks
-- ============================================================

-- Safety properties (should hold)
check ctvNoUnauthorizedExtraction_NoKey for 6 but 5 Int, 8 Time
check ctvCSVEnforced for 6 but 5 Int, 8 Time
check ctvNoStateProliferation for 6 but 5 Int, 8 Time

-- Should find counterexample: hot key holder CAN extract
check ctvNoExtraction_HotKeyOnly for 6 but 5 Int, 8 Time

-- Liveness (should find counterexample via address reuse)
check ctvEventualWithdrawal for 6 but 5 Int, 8 Time

-- Recovery liveness (should hold for CTV — no key needed)
check ctvRecoveryAlwaysPossible for 6 but 5 Int, 8 Time

-- ============================================================
-- Instance generation for visualization
-- ============================================================

-- Generate a normal CTV lifecycle: vault -> unvault -> withdraw
pred ctvNormalLifecycle {
  some f : CTVVaultFamily |
    some t : CTVTrigger | t.family = f and
    some w : CTVWithdraw | w.family = f
}
run ctvNormalLifecycle for 6 but 5 Int, 8 Time

-- Generate an address reuse scenario
pred ctvAddressReuseScenario {
  some disj f1, f2 : CTVVaultFamily |
    addressReuse[f1, f2]
}
run ctvAddressReuseScenario for 8 but 5 Int, 10 Time

-- Generate a recovery scenario
pred ctvRecoveryScenario {
  some f : CTVVaultFamily |
    some t : CTVTrigger | t.family = f and
    some r : CTVRecover | r.family = f
}
run ctvRecoveryScenario for 6 but 5 Int, 8 Time
