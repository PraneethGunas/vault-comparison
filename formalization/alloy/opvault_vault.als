/**
 * opvault_vault.als — OP_VAULT (BIP-345) Vault Model
 *
 * State machine:
 *   VAULT -> TRIGGER -> {WITHDRAWN, RECOVERED}
 *   VAULT -> (TRIGGER, VAULT) via automatic revault on partial withdrawal
 *   {VAULT, TRIGGER} -> RECOVERED [AUTHORIZED — requires recoveryauth_key]
 *
 * Key structure (three-key separation):
 *   - trigger_key: xpub-derived (BIP-32 m/0h/0), initiates withdrawal
 *   - recoveryauth_key: authorizes recovery (anti-griefing)
 *   - recovery_key: destination only (funds go here, never used for signing)
 *
 * Fee wallet: OP_VAULT requires a separate fee wallet UTXO as a second
 * input for trigger and recovery transactions. This is modeled explicitly
 * because fee wallet contention is a novel attack vector.
 *
 * Capabilities: automatic revault, batched triggers, authorized recovery
 */
module opvault_vault

open btc_base
open vault_base
open threat_model

-- ============================================================
-- Fee Wallet: explicit resource for OP_VAULT operations
-- ============================================================
sig FeeWalletUTXO extends UTXO {} {
  value > 0
  -- Fee wallet UTXOs are NOT part of any vault family
  -- They are a shared resource
}

-- Fee Wallet: collection of available fee UTXOs
one sig FeeWallet {
  utxos : set FeeWalletUTXO
}

-- A fee UTXO is available if it hasn't been spent
fun availableFeeUTXOs : set FeeWalletUTXO {
  { u : FeeWallet.utxos | live[u] }
}

-- ============================================================
-- OP_VAULT-specific vault UTXOs
-- ============================================================

sig OPVaultUTXO extends VaultUTXO {
  recoveryAddr    : one Address,    -- pre-committed, immutable
  recoveryAuthKey : one Key         -- needed to authorize recovery
} {
  status = VAULTED
  recoveryAuthKey = RecoveryAuthKey
}

-- CTVTemplate is defined in vault_base.als (shared across all three vaults)

sig OPVaultTriggerUTXO extends VaultUTXO {
  ctvTemplate     : one CTVTemplate,    -- withdrawal destination (CTV-locked)
  recoveryAddr    : one Address,
  recoveryAuthKey : one Key
} {
  status = UNVAULTING
  recoveryAuthKey = RecoveryAuthKey
}

sig OPVaultWithdrawnUTXO extends VaultUTXO {} {
  status = WITHDRAWN
}

sig OPVaultRecoveredUTXO extends VaultUTXO {} {
  status = RECOVERED
}

-- ============================================================
-- OP_VAULT Family
-- ============================================================
sig OPVaultFamily extends VaultFamily {
  triggerKey      : one Key,
  recoveryAuthKey : one Key,
  recoveryDestKey : one Key,
  recoveryAddr    : one Address
} {
  triggerKey = TriggerKey
  recoveryAuthKey = RecoveryAuthKey
  recoveryDestKey = RecoveryDestKey
  -- Recovery address is pre-committed and immutable
  coldAddr = recoveryAddr
  coldAddr.owner = RecoveryDestKey
}

-- ============================================================
-- OP_VAULT Transitions
-- ============================================================

-- Trigger: VAULT -> TRIGGER
-- Requires: trigger_key Schnorr signature
-- 2-input structure: vault UTXO + fee wallet UTXO
-- 3-output structure: trigger UTXO + optional revault UTXO + fee change
sig OPVaultTrigger extends TriggerTransition {
  feeInput      : one FeeWalletUTXO,   -- required fee wallet input
  withdrawDest  : one Address,          -- chosen at trigger time
  feeChange     : lone UTXO            -- change back to fee wallet
} {
  src in OPVaultUTXO
  all d : dst | d in OPVaultTriggerUTXO
  -- Requires trigger key signature
  TriggerKey in txn.signers
  -- Fee wallet input must be in the transaction
  feeInput in txn.inputs
  -- Fee input must be available (not already spent)
  feeInput.spent = txn
  -- Fee change goes back to fee wallet (if any)
  some feeChange implies feeChange in txn.outputs
  -- Recovery address propagates
  all d : dst | (d :> OPVaultTriggerUTXO).recoveryAddr =
    (src :> OPVaultUTXO).recoveryAddr
}

-- Revault: VAULT -> (TRIGGER, VAULT) [automatic partial withdrawal]
sig OPVaultRevault extends RevaultTransition {
  feeInput     : one FeeWalletUTXO,
  withdrawDest : one Address,
  feeChange    : lone UTXO
} {
  src in OPVaultUTXO
  -- Requires trigger key
  TriggerKey in txn.signers
  -- Fee wallet input
  feeInput in txn.inputs
  feeInput.spent = txn
  -- Produces trigger UTXO + new vault UTXO
  some d : dst | d in OPVaultTriggerUTXO
  some d : dst | d in OPVaultUTXO
  -- Recovery address propagates to both children
  all d : dst | d.status = VAULTED implies
    (d :> OPVaultUTXO).recoveryAddr = (src :> OPVaultUTXO).recoveryAddr
  all d : dst | d.status = UNVAULTING implies
    (d :> OPVaultTriggerUTXO).recoveryAddr = (src :> OPVaultUTXO).recoveryAddr
}

-- Withdrawal: TRIGGER -> WITHDRAWN
-- Requires: CSV + CTV template match (no signature)
sig OPVaultWithdraw extends WithdrawTransition {} {
  src in OPVaultTriggerUTXO
  all d : dst | d in OPVaultWithdrawnUTXO
  -- CTV template match (no signature needed)
  -- CSV enforced by parent class
}

-- Recovery: {VAULT, TRIGGER} -> RECOVERED
-- AUTHORIZED: requires recoveryauth_key Schnorr signature
-- 2-input structure: vault/trigger UTXO + fee wallet UTXO
sig OPVaultRecover extends RecoverTransition {
  feeInput : one FeeWalletUTXO   -- required fee wallet input
} {
  src.status in (VAULTED + UNVAULTING)
  all d : dst | d in OPVaultRecoveredUTXO
  -- AUTHORIZED: requires recoveryauth key
  RecoveryAuthKey in txn.signers
  -- Fee wallet input required
  feeInput in txn.inputs
  feeInput.spent = txn
  -- Recovery goes to pre-committed address
  -- (enforced by parent RecoverTransition → coldAddr)
}

-- ============================================================
-- OP_VAULT closing axioms: tie UTXO subtypes to transition types
-- ============================================================
fact opvClosingAxioms {
  -- Every OPVaultWithdrawnUTXO must be produced by exactly one OPVaultWithdraw
  all u : OPVaultWithdrawnUTXO | one w : OPVaultWithdraw | u in w.dst

  -- Every OPVaultRecoveredUTXO must be produced by exactly one OPVaultRecover
  all u : OPVaultRecoveredUTXO | one r : OPVaultRecover | u in r.dst

  -- Every OPVaultTriggerUTXO must be produced by exactly one trigger or revault
  all u : OPVaultTriggerUTXO |
    (one t : OPVaultTrigger | u in t.dst) or (one r : OPVaultRevault | u in r.dst)

  -- Every OPVaultUTXO that is not a deposit comes from a revault
  all u : OPVaultUTXO | u not in VaultFamily.deposit implies
    one r : OPVaultRevault | u in r.dst
}

-- ============================================================
-- OP_VAULT transition cardinality: constrain output counts
-- (Fix R2-2: prevents multi-output triggers/withdrawals)
-- ============================================================
fact opvTransitionCardinality {
  -- OPV trigger produces exactly one trigger UTXO
  all t : OPVaultTrigger | #t.dst = 1

  -- OPV revault produces exactly two outputs: one TRIGGER + one VAULT
  all r : OPVaultRevault | #r.dst = 2 and
    one (r.dst & OPVaultTriggerUTXO) and one (r.dst & OPVaultUTXO)

  -- OPV withdrawal produces exactly one withdrawn UTXO
  all w : OPVaultWithdraw | #w.dst = 1

  -- OPV recovery produces exactly one recovered UTXO
  all r : OPVaultRecover | #r.dst = 1
}

-- ============================================================
-- OP_VAULT family well-formedness: allUTXOs contains only OPV-typed UTXOs
-- ============================================================
fact opvFamilyWellFormedness {
  -- An OPVaultFamily's allUTXOs only contains OPV-subtyped VaultUTXOs
  all f : OPVaultFamily |
    f.allUTXOs in (OPVaultUTXO + OPVaultTriggerUTXO + OPVaultWithdrawnUTXO + OPVaultRecoveredUTXO)

  -- All OPV-subtyped UTXOs belong to an OPVaultFamily
  all u : (OPVaultUTXO + OPVaultTriggerUTXO + OPVaultWithdrawnUTXO + OPVaultRecoveredUTXO) |
    u.vaultFamily in OPVaultFamily
}

-- ============================================================
-- Fee wallet population: ensure non-degenerate fee wallet
-- ============================================================
fact feeWalletPopulated {
  -- The fee wallet has at least one UTXO
  some FeeWallet.utxos

  -- Fee wallet UTXOs are not part of any vault family
  all u : FeeWalletUTXO | u not in VaultUTXO
}

-- ============================================================
-- FEE WALLET CONTENTION MODEL (Property 11 — novel)
-- ============================================================

-- Helper: extract the fee input from a trigger or recovery transition
fun feeInputOf[t: OPVaultTrigger] : one FeeWalletUTXO { t.feeInput }
fun feeInputOfR[r: OPVaultRecover] : one FeeWalletUTXO { r.feeInput }

-- Two recovery operations competing for the same fee wallet UTXO
pred feeWalletContention[r1, r2: OPVaultRecover] {
  r1 != r2
  r1.feeInput = r2.feeInput
}

-- Trigger and recovery competing for the same fee wallet UTXO
pred feeWalletContentionTR[t: OPVaultTrigger, r: OPVaultRecover] {
  t.feeInput = r.feeInput
}

-- Can triggering one vault's recovery consume the fee UTXO
-- needed for another vault's recovery?
-- (Fix R2-4: r2 CANNOT confirm because r1 already spent the shared input)
pred recoveryBlockedByContention[f1, f2: OPVaultFamily] {
  f1 != f2
  some r1 : OPVaultRecover, r2 : OPVaultRecover |
    r1.family = f1 and r2.family = f2 and
    feeWalletContention[r1, r2] and
    -- r1 confirms, consuming the shared fee UTXO
    some r1.txn.confirmTime and
    -- r2 CANNOT confirm: its fee input was spent by r1
    no r2.txn.confirmTime
}

-- ============================================================
-- THREE-KEY SEPARATION ANALYSIS
-- ============================================================

-- With only trigger key: can initiate withdrawal but watchtower
-- can recover (if it has recoveryauth key)
pred triggerKeyOnlyAttack {
  opvTriggerKeyOnly
  -- Attacker can trigger, setting destination to AttackerAddr
  some t : OPVaultTrigger | t.withdrawDest = AttackerAddr
}

-- With only recoveryauth key: can only recover to pre-committed
-- address (not attacker-controlled)
pred recoveryAuthOnlyAttack {
  opvRecoveryAuthOnly
  -- Attacker can recover but funds go to owner's recovery address
  some r : OPVaultRecover | r.src.status in (VAULTED + UNVAULTING)
  -- Cannot redirect recovery funds
}

-- Dual-key compromise: trigger + recoveryauth
-- Can trigger AND front-run watchtower's recovery
-- But still cannot redirect recovery to attacker address
pred dualKeyAttack {
  opvDualKey
  -- Attacker triggers withdrawal to their address
  some t : OPVaultTrigger | t.withdrawDest = AttackerAddr
  -- Attacker can also invoke recovery (but funds go to owner)
  some r : OPVaultRecover | r.src.status in (VAULTED + UNVAULTING)
  -- Result: indefinite liveness denial, NOT theft
}

-- ============================================================
-- RECOVERYAUTH KEY LOSS MODEL
-- ============================================================

-- If recoveryauth key is lost, recovery becomes impossible
-- (unlike CCV where recovery is keyless)
pred recoveryAuthKeyLost[f: OPVaultFamily] {
  -- The recoveryauth key exists but nobody can sign with it
  -- (not in any honest party's possession and not in Attacker.controls)
  f.recoveryAuthKey not in Attacker.controls
  -- Model: no recovery transition can be created for this family
  no r : OPVaultRecover | r.family = f
}

-- ============================================================
-- PROPERTY CHECKS: OP_VAULT-specific
-- ============================================================

-- Property 2: No unauthorized extraction without trigger key
assert opvNoExtraction_NoKey {
  noKeyAttacker implies
    no u : OPVaultWithdrawnUTXO | u.script = AttackerAddr
}

-- Property 2: Trigger key alone should allow extraction attempt
-- (but watchtower can recover). Check that trigger key IS sufficient
-- to reach WITHDRAWN if no recovery happens.
assert opvNoExtraction_TriggerKey {
  opvTriggerKeyOnly implies
    no u : OPVaultWithdrawnUTXO | u.script = AttackerAddr
}

-- Property 3: Recovery destination integrity
-- Even with dual-key compromise, recovery goes to pre-committed addr
assert opvRecoveryIntegrity {
  all r : OPVaultRecover, d : r.dst |
    d.script = r.family.coldAddr and d.script != AttackerAddr
}

-- Property 5: CSV enforcement on withdrawal
assert opvCSVEnforced {
  all w : OPVaultWithdraw |
    csvSatisfied[w.src, w.txn, w.src.csvDelay]
}

-- Property 7: Recovery always possible (SHOULD FAIL)
-- OP_VAULT recovery requires recoveryauth key — key loss blocks recovery
assert opvRecoveryAlwaysPossible {
  all f : OPVaultFamily |
    all u : f.allUTXOs |
      (u.status in (VAULTED + UNVAULTING) and live[u]) implies
        some r : OPVaultRecover | r.src = u
}

-- Property 8: No state proliferation (SHOULD FAIL)
-- OP_VAULT revault creates splits just like CCV
assert opvBoundedState {
  all f : OPVaultFamily | #{u : f.allUTXOs | u.status in (VAULTED + UNVAULTING)} <= 3
}

-- Property 11: Fee wallet contention (NOVEL — should find instance)
-- Can recovery of one vault be blocked by another vault's operation?
assert opvNoFeeContention {
  all disj f1, f2 : OPVaultFamily |
    not recoveryBlockedByContention[f1, f2]
}

-- Property: Dual-key compromise cannot steal funds
-- (can only deny liveness by cycling trigger -> recover)
assert opvDualKeyNoTheft {
  opvDualKey implies
    (all r : OPVaultRecover, d : r.dst | d.script != AttackerAddr)
}

-- ============================================================
-- Checks
-- ============================================================

-- Safety (should hold)
check opvNoExtraction_NoKey for 6 but 5 Int, 8 Time
check opvRecoveryIntegrity for 6 but 5 Int, 8 Time
check opvCSVEnforced for 6 but 5 Int, 8 Time
check opvDualKeyNoTheft for 6 but 5 Int, 8 Time

-- Should find counterexample (trigger key CAN set destination)
check opvNoExtraction_TriggerKey for 6 but 5 Int, 8 Time

-- Recovery liveness (should FAIL — key loss)
check opvRecoveryAlwaysPossible for 6 but 5 Int, 8 Time

-- State proliferation (should FAIL — revault loop)
check opvBoundedState for 8 but 5 Int, 10 Time

-- Fee wallet contention (NOVEL — should find counterexample now with populated fee wallet)
check opvNoFeeContention for 8 but 5 Int, 10 Time

-- ============================================================
-- Instance generation
-- ============================================================

-- Normal OP_VAULT lifecycle
pred opvNormalLifecycle {
  some f : OPVaultFamily |
    some t : OPVaultTrigger | t.family = f and
    some w : OPVaultWithdraw | w.family = f
}
run opvNormalLifecycle for 8 but 5 Int, 10 Time

-- Recovery with fee wallet
pred opvRecoveryScenario {
  some f : OPVaultFamily |
    some t : OPVaultTrigger | t.family = f and
    some r : OPVaultRecover | r.family = f
}
run opvRecoveryScenario for 8 but 5 Int, 10 Time

-- Fee wallet contention scenario
-- Force two families and a limited fee pool so contention can arise
pred opvFeeContentionScenario {
  #{OPVaultFamily} >= 2
  #{FeeWallet.utxos} = 1  -- scarce fee wallet: only one UTXO
  some disj f1, f2 : OPVaultFamily |
    recoveryBlockedByContention[f1, f2]
}
run opvFeeContentionScenario for 10 but 5 Int, 12 Time

-- Splitting attack
pred opvSplittingScenario {
  some f : OPVaultFamily |
    #{r : OPVaultRevault | r.family = f} >= 3
}
run opvSplittingScenario for 10 but 5 Int, 12 Time

-- Dual-key liveness denial
pred opvDualKeyDenial {
  opvDualKey and
  some f : OPVaultFamily |
    some t : OPVaultTrigger | t.family = f and
    some r : OPVaultRecover | r.family = f
}
run opvDualKeyDenial for 8 but 5 Int, 10 Time

-- Key loss blocks recovery
pred opvKeyLossScenario {
  some f : OPVaultFamily |
    recoveryAuthKeyLost[f] and
    some t : OPVaultTrigger | t.family = f
    -- Trigger exists but no recovery possible
}
run opvKeyLossScenario for 6 but 5 Int, 8 Time
