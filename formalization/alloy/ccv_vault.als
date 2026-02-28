/**
 * ccv_vault.als — CCV (BIP-443) Vault Model
 *
 * State machine:
 *   VAULT -> UNVAULTING -> {WITHDRAWN, RECOVERED}
 *   VAULT -> (UNVAULTING, VAULT) via trigger_and_revault [partial withdrawal loop]
 *   {VAULT, UNVAULTING} -> RECOVERED [keyless recovery]
 *
 * CCV semantics:
 *   - Enforces output structure via <data> <index> <pk> <taptree> <mode> CCV
 *   - Destination chosen at trigger time (not vault creation)
 *   - NUMS internal key prevents taproot keypath spend
 *   - Misconfiguration: real pubkey as internal_key -> keypath bypass
 *
 * Key requirements:
 *   - VAULT -> UNVAULTING: unvault_key Schnorr signature
 *   - UNVAULTING -> WITHDRAWN: CSV + CTV template (no signature)
 *   - {VAULT, UNVAULTING} -> RECOVERED: KEYLESS (no signature at all)
 *
 * Capabilities: revault (chainable), batched triggers, keyless recovery
 */
module ccv_vault

open btc_base
open vault_base
open threat_model

-- ============================================================
-- CCV Mode: the checking mode parameter
-- ============================================================
abstract sig CCVMode {}
one sig CheckOutput extends CCVMode {}       -- mode 0: check output structure
one sig DeductOutput extends CCVMode {}      -- mode 1: deduct from output amount
one sig CheckInput extends CCVMode {}        -- mode 2: check input structure
one sig CheckInputDeduct extends CCVMode {}  -- mode 3: check input + deduct

-- Undefined modes: 4, 7, 128, 255 → trigger OP_SUCCESS
sig UndefinedMode extends CCVMode {} {
  -- Any mode value not in {0,1,2,3}
  -- OP_SUCCESS: script succeeds unconditionally
}

-- ============================================================
-- CCV Contract: Taproot structure with covenant leaves
-- ============================================================
sig CCVContract {
  internalKey   : lone Key,     -- should be NUMS (none); real key = keypath bypass
  triggerLeaf   : one CCVMode,
  recoverLeaf   : one CCVMode,
  isNUMS        : one Bool       -- is the internal key a NUMS point?
}

-- Boolean helper for Alloy (no built-in Bool in Alloy 4)
abstract sig Bool {}
one sig True, False extends Bool {}

-- ============================================================
-- CCV-specific vault UTXOs
-- ============================================================

sig CCVVaultUTXO extends VaultUTXO {
  contract : one CCVContract
} {
  status = VAULTED
}

-- CTVTemplate is defined in vault_base.als (shared across all three vaults)
-- CCV uses CTV for the final withdrawal step

sig CCVUnvaultingUTXO extends VaultUTXO {
  ctvHash : one CTVTemplate    -- set at trigger time (late binding)
} {
  status = UNVAULTING
}

sig CCVWithdrawnUTXO extends VaultUTXO {} {
  status = WITHDRAWN
}

sig CCVRecoveredUTXO extends VaultUTXO {} {
  status = RECOVERED
}

-- ============================================================
-- CCV Vault Family
-- ============================================================
sig CCVVaultFamily extends VaultFamily {
  unvaultKey  : one Key,
  recoverPK   : one Key,    -- destination only, NOT for signing
  contract    : one CCVContract
} {
  unvaultKey = UnvaultKey
  recoverPK = RecoverPubKey
  -- Cold address is derived from recoverPK
  coldAddr.owner = RecoverPubKey
}

-- ============================================================
-- CCV Transitions
-- ============================================================

-- Trigger: VAULT -> UNVAULTING
-- Requires unvault_key Schnorr signature
-- Destination chosen at trigger time (CTV hash embedded)
sig CCVTrigger extends TriggerTransition {
  withdrawalDest : one Address   -- chosen at trigger time
} {
  src in CCVVaultUTXO
  all d : dst | d in CCVUnvaultingUTXO
  #dst = 1
  -- Requires unvault key signature
  UnvaultKey in txn.signers
  -- CCV validates output structure
  -- The trigger embeds the CTV hash for the final withdrawal
}

-- Revault: VAULT -> (UNVAULTING, VAULT)
-- Partial withdrawal — creates two outputs
sig CCVRevault extends RevaultTransition {
  withdrawalDest : one Address,
  withdrawAmount : one Int,
  remainAmount   : one Int
} {
  src in CCVVaultUTXO
  -- Requires unvault key
  UnvaultKey in txn.signers
  -- Two outputs: one UNVAULTING, one new VAULT
  some d : dst | d.status = UNVAULTING and d in CCVUnvaultingUTXO
  some d : dst | d.status = VAULTED and d in CCVVaultUTXO
  -- Value conservation (minus fee)
  withdrawAmount > 0
  remainAmount > 0
  plus[withdrawAmount, remainAmount] <= src.value
  -- The new vault UTXO has the SAME contract (chainable)
  all d : dst | d.status = VAULTED implies
    (d :> CCVVaultUTXO).contract = (src :> CCVVaultUTXO).contract
}

-- Withdrawal: UNVAULTING -> WITHDRAWN
-- Requires CSV + CTV template match (no signature)
sig CCVWithdraw extends WithdrawTransition {} {
  src in CCVUnvaultingUTXO
  all d : dst | d in CCVWithdrawnUTXO
  -- No signature needed — CTV template match only
  -- CSV enforced by parent class
}

-- Recovery: {VAULT, UNVAULTING} -> RECOVERED
-- KEYLESS: no signature required, anyone can invoke
sig CCVRecover extends RecoverTransition {} {
  src.status in (VAULTED + UNVAULTING)
  all d : dst | d in CCVRecoveredUTXO
  -- KEYLESS: explicitly NO signer required
  -- This is the griefing vector: any node can front-run trigger with recovery
}

-- ============================================================
-- WildSpend: unstructured spending via OP_SUCCESS (mode confusion)
-- (Fix R2-3: models the fact that OP_SUCCESS bypasses all covenant checks)
-- ============================================================
sig CCVWildSpend extends Transition {} {
  -- Source must be a CCV vault UTXO with mode confusion
  src in CCVVaultUTXO
  modeConfusion[(src :> CCVVaultUTXO).contract]

  -- OP_SUCCESS: script succeeds unconditionally, no signer needed,
  -- attacker can send funds anywhere (including AttackerAddr)
  -- dst contains whatever UTXOs the attacker creates (not vault-typed)
  #dst = 0  -- outputs are plain UTXOs, not VaultUTXOs

  -- The spend is recorded in the base UTXO graph
  src.spent = txn
}

-- ============================================================
-- CCV closing axioms: tie UTXO subtypes to transition types
-- ============================================================
fact ccvClosingAxioms {
  -- Every CCVWithdrawnUTXO must be produced by exactly one CCVWithdraw
  all u : CCVWithdrawnUTXO | one w : CCVWithdraw | u in w.dst

  -- Every CCVRecoveredUTXO must be produced by exactly one CCVRecover
  all u : CCVRecoveredUTXO | one r : CCVRecover | u in r.dst

  -- Every CCVUnvaultingUTXO must be produced by exactly one trigger or revault
  all u : CCVUnvaultingUTXO |
    (one t : CCVTrigger | u in t.dst) or (one r : CCVRevault | u in r.dst)

  -- Every CCVVaultUTXO that is not a deposit comes from a revault
  all u : CCVVaultUTXO | u not in VaultFamily.deposit implies
    one r : CCVRevault | u in r.dst

  -- WEAKENED for WildSpend: a spent CCV vault UTXO can be consumed by
  -- either a normal transition OR a WildSpend (if mode confusion applies)
}

-- ============================================================
-- CCV transition cardinality: constrain output counts
-- (Fix R2-2: prevents multi-output triggers/withdrawals)
-- ============================================================
fact ccvTransitionCardinality {
  -- CCV trigger produces exactly one unvaulting UTXO
  all t : CCVTrigger | #t.dst = 1

  -- CCV revault produces exactly two outputs: one UNVAULTING + one VAULTED
  all r : CCVRevault | #r.dst = 2 and
    one (r.dst & CCVUnvaultingUTXO) and one (r.dst & CCVVaultUTXO)

  -- CCV withdrawal produces exactly one withdrawn UTXO
  all w : CCVWithdraw | #w.dst = 1

  -- CCV recovery produces exactly one recovered UTXO
  all r : CCVRecover | #r.dst = 1
}

-- ============================================================
-- CCV family well-formedness: allUTXOs contains only CCV-typed UTXOs
-- ============================================================
fact ccvFamilyWellFormedness {
  -- A CCVVaultFamily's allUTXOs only contains CCV-subtyped VaultUTXOs
  all f : CCVVaultFamily |
    f.allUTXOs in (CCVVaultUTXO + CCVUnvaultingUTXO + CCVWithdrawnUTXO + CCVRecoveredUTXO)

  -- All CCV-subtyped UTXOs belong to a CCVVaultFamily
  all u : (CCVVaultUTXO + CCVUnvaultingUTXO + CCVWithdrawnUTXO + CCVRecoveredUTXO) |
    u.vaultFamily in CCVVaultFamily
}

-- ============================================================
-- MODE CONFUSION VULNERABILITY
-- ============================================================

-- If a contract uses an undefined mode, OP_SUCCESS fires:
-- script succeeds unconditionally, zero covenant enforcement.
pred modeConfusion[c: CCVContract] {
  c.triggerLeaf in UndefinedMode or c.recoverLeaf in UndefinedMode
}

-- Under mode confusion, anyone can spend the UTXO (no covenant)
pred modeConfusionExploit[u: CCVVaultUTXO] {
  modeConfusion[u.contract]
  -- When OP_SUCCESS fires, no covenant checks are performed
  -- Any transaction can spend this UTXO
}

-- ============================================================
-- KEYPATH BYPASS VULNERABILITY
-- ============================================================

-- If internal_key is a real pubkey (not NUMS), the keypath spend
-- bypasses all taptree covenant enforcement
pred keypathBypass[c: CCVContract] {
  c.isNUMS = False and some c.internalKey
}

-- An attacker with the internal key can drain the vault
pred keypathExploit[u: CCVVaultUTXO] {
  keypathBypass[u.contract] and
  u.contract.internalKey in Attacker.controls
}

-- ============================================================
-- KEYLESS RECOVERY GRIEFING MODEL
-- ============================================================

-- The griefing loop: attacker triggers recovery, owner re-vaults,
-- attacker triggers recovery again. Cost asymmetry:
-- trigger_and_revault = ~162 vB (owner) vs recovery = ~122 vB (attacker)

-- Count of griefing rounds (bounded by scope)
pred griefingLoop[f: CCVVaultFamily, rounds: Int] {
  rounds > 0
  -- There exist `rounds` alternating trigger-recover sequences
  -- Each round: owner triggers, attacker front-runs with recovery
  #{r : CCVRecover | r.family = f} >= rounds
}

-- ============================================================
-- STATE PROLIFERATION (SPLITTING ATTACK)
-- ============================================================

-- The revault loop creates unbounded splits. Each revault produces
-- a new vault UTXO that can itself be revaulted.

-- Count of vault UTXOs in a family (should be bounded)
fun vaultUTXOCount[f: CCVVaultFamily] : Int {
  #{u : f.allUTXOs | u.status = VAULTED or u.status = UNVAULTING}
}

-- Splitting: attacker with trigger key repeatedly revaults
pred splittingAttack[f: CCVVaultFamily] {
  -- Multiple revault transitions from the same family
  #{r : CCVRevault | r.family = f} > 1
}

-- ============================================================
-- PROPERTY CHECKS: CCV-specific
-- ============================================================

-- Property 2 (CCV): No unauthorized extraction
-- Without unvault key, attacker cannot set withdrawal destination
assert ccvNoExtraction_NoKey {
  ccvNoKey implies
    no u : CCVWithdrawnUTXO | u.script = AttackerAddr
}

-- With trigger key, attacker CAN set destination (should find counterexample)
assert ccvNoExtraction_TriggerKey {
  ccvTriggerKeyOnly implies
    no u : CCVWithdrawnUTXO | u.script = AttackerAddr
}

-- Property 3: Recovery destination integrity (should hold)
-- Keyless recovery still goes to pre-committed address
assert ccvRecoveryIntegrity {
  all r : CCVRecover, d : r.dst |
    d.script = r.family.coldAddr
}

-- Property 6: Eventual withdrawal (should hold without griefing)
assert ccvEventualWithdrawal {
  all f : CCVVaultFamily |
    (not modeConfusion[f.contract]) implies canWithdraw[f]
}

-- Property 7: Recovery always possible (SHOULD HOLD — keyless)
-- This is the flip side of the griefing vector: recovery is always
-- available because it requires no key.
assert ccvRecoveryAlwaysPossible {
  all f : CCVVaultFamily |
    all u : f.allUTXOs |
      (u.status in (VAULTED + UNVAULTING) and live[u]) implies
        some r : CCVRecover | r.src = u
}

-- Property 8: No state proliferation (SHOULD FAIL)
-- Revault loop creates unbounded UTXO count
assert ccvBoundedState {
  all f : CCVVaultFamily | vaultUTXOCount[f] <= 3
}

-- Property: Mode confusion — can OP_SUCCESS drain funds outside the vault?
-- ccvNoModeConfusionBypass: every spend goes through SOME transition (holds by construction)
assert ccvNoModeConfusionBypass {
  all u : CCVVaultUTXO | some u.spent implies
    (some t : Transition | t.src = u)
}

-- ccvModeConfusionEnablesDrain: with mode confusion, a WildSpend can consume
-- vault funds without routing through withdraw/recover (SHOULD find counterexample)
-- The attacker spends the UTXO via OP_SUCCESS; the vault outputs disappear
-- into plain (non-vault) UTXOs the attacker controls.
assert ccvModeConfusionContained {
  -- No WildSpend transition exists (i.e., mode confusion never enables wild spending)
  no CCVWildSpend
}

-- ============================================================
-- Checks
-- ============================================================

-- Safety (should hold)
check ccvNoExtraction_NoKey for 6 but 5 Int, 8 Time
check ccvRecoveryIntegrity for 6 but 5 Int, 8 Time

-- Should find counterexample: trigger key holder CAN extract
check ccvNoExtraction_TriggerKey for 6 but 5 Int, 8 Time

-- Keyless recovery always available (should hold)
check ccvRecoveryAlwaysPossible for 6 but 5 Int, 8 Time

-- State proliferation (should find counterexample at scope >= 4)
check ccvBoundedState for 8 but 5 Int, 10 Time

-- Mode confusion bypass (should hold: closing axioms prevent orphan spending)
check ccvNoModeConfusionBypass for 6 but 5 Int, 8 Time

-- Mode confusion contained (should find counterexample: OP_SUCCESS breaks covenant)
check ccvModeConfusionContained for 6 but 5 Int, 8 Time

-- ============================================================
-- Instance generation
-- ============================================================

-- Normal CCV lifecycle with revault
pred ccvRevaultLifecycle {
  some f : CCVVaultFamily |
    some r : CCVRevault | r.family = f and
    some w : CCVWithdraw | w.family = f
}
run ccvRevaultLifecycle for 8 but 5 Int, 10 Time

-- Keyless griefing scenario
pred ccvGriefingScenario {
  some f : CCVVaultFamily |
    noKeyAttacker and
    #{r : CCVRecover | r.family = f} >= 2
}
run ccvGriefingScenario for 8 but 5 Int, 10 Time

-- Splitting attack: multiple revaults from one family
pred ccvSplittingScenario {
  some f : CCVVaultFamily |
    #{r : CCVRevault | r.family = f} >= 3
}
run ccvSplittingScenario for 10 but 5 Int, 12 Time

-- Mode confusion exploit
pred ccvModeConfusionScenario {
  some u : CCVVaultUTXO | modeConfusionExploit[u]
}
run ccvModeConfusionScenario for 6 but 5 Int, 8 Time

-- Keypath bypass exploit
pred ccvKeypathBypassScenario {
  some u : CCVVaultUTXO | keypathExploit[u]
}
run ccvKeypathBypassScenario for 6 but 5 Int, 8 Time
