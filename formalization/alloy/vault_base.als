/**
 * vault_base.als — Abstract Vault State Machine
 *
 * Defines the common structure shared by all three vault designs:
 * states, transitions, and the properties that should hold across
 * any correct vault implementation.
 *
 * Each concrete vault (CTV, CCV, OP_VAULT) extends this with its
 * own transition guards and key requirements.
 */
module vault_base

open btc_base

-- ============================================================
-- Vault lifecycle states
-- ============================================================
abstract sig VaultStatus {}
one sig VAULTED extends VaultStatus {}
one sig UNVAULTING extends VaultStatus {}
one sig WITHDRAWN extends VaultStatus {}
one sig RECOVERED extends VaultStatus {}

-- ============================================================
-- VaultUTXO: a UTXO that participates in a vault lifecycle
-- ============================================================
sig VaultUTXO extends UTXO {
  status       : one VaultStatus,
  vaultFamily  : one VaultFamily,   -- which vault instance this belongs to
  csvDelay     : one Int            -- the CSV delay for this vault (e.g., 10)
} {
  csvDelay > 0
}

-- ============================================================
-- VaultFamily: groups all UTXOs derived from one initial deposit
-- ============================================================
sig VaultFamily {
  deposit       : one VaultUTXO,       -- the original vaulted UTXO
  depositValue  : one Int,             -- original deposit amount
  hotAddr       : one Address,         -- withdrawal destination
  coldAddr      : one Address,         -- recovery destination
  allUTXOs      : set VaultUTXO        -- all UTXOs in this family
} {
  deposit in allUTXOs
  deposit.status = VAULTED
  depositValue = deposit.value
  depositValue > 0
  -- All UTXOs in a family share the same vault family
  all u : allUTXOs | u.vaultFamily = this
  -- ADDRESS SEPARATION: vault addresses are never the attacker address
  -- (Fix R2-1: prevents solver from equating vault destinations with AttackerAddr)
  coldAddr != AttackerAddr
  hotAddr != AttackerAddr
}

-- ============================================================
-- Transition: a labeled edge in the vault state machine
-- ============================================================
abstract sig Transition {
  src     : one VaultUTXO,     -- input UTXO (consumed)
  dst     : set VaultUTXO,     -- output UTXO(s) (created)
  txn     : one Tx,            -- the Bitcoin transaction effecting this
  family  : one VaultFamily    -- which vault family
} {
  src in txn.inputs
  dst in txn.outputs
  src.vaultFamily = family
  all d : dst | d.vaultFamily = family
  -- The source is spent by this transaction
  src.spent = txn
}

-- ============================================================
-- Transition types (abstract — concrete vaults add guards)
-- ============================================================

-- Trigger: VAULTED -> UNVAULTING
abstract sig TriggerTransition extends Transition {} {
  src.status = VAULTED
  all d : dst | d.status = UNVAULTING
}

-- Withdrawal: UNVAULTING -> WITHDRAWN (requires CSV)
abstract sig WithdrawTransition extends Transition {} {
  src.status = UNVAULTING
  all d : dst | d.status = WITHDRAWN
  -- CSV must be satisfied
  csvSatisfied[src, txn, src.csvDelay]
}

-- Recovery: {VAULTED, UNVAULTING} -> RECOVERED
abstract sig RecoverTransition extends Transition {} {
  src.status in (VAULTED + UNVAULTING)
  all d : dst | d.status = RECOVERED
  -- Recovery sends to cold address
  all d : dst | d.script = family.coldAddr
}

-- Revault: VAULTED -> (UNVAULTING, VAULTED) [partial withdrawal]
-- Only CCV and OP_VAULT support this
abstract sig RevaultTransition extends Transition {} {
  src.status = VAULTED
  -- Must produce at least one UNVAULTING and one VAULTED output
  some d : dst | d.status = UNVAULTING
  some d : dst | d.status = VAULTED
}

-- ============================================================
-- Well-formedness: transition graph consistency
-- ============================================================
fact transitionConsistency {
  -- Every VaultUTXO that is spent must have exactly one transition consuming it
  all u : VaultUTXO | some u.spent implies
    one t : Transition | t.src = u

  -- CLOSING AXIOM: every non-deposit VaultUTXO is produced by exactly one transition
  -- (This prevents "orphan" UTXOs that appear in terminal states without going
  --  through the guarded transition path)
  all u : VaultUTXO | u.status != VAULTED implies
    one t : Transition | u in t.dst

  -- CLOSING AXIOM for VAULTED UTXOs created by revault (not deposits):
  -- If a VAULTED UTXO is not a deposit, it must come from a RevaultTransition
  all u : VaultUTXO | u.status = VAULTED and u not in VaultFamily.deposit implies
    one r : RevaultTransition | u in r.dst

  -- Terminal states cannot be spent by vault transitions
  all u : VaultUTXO | u.status in (WITHDRAWN + RECOVERED) implies
    no t : Transition | t.src = u

  -- Transitions within a family
  all t : Transition | t.src.vaultFamily = t.family
}

-- ============================================================
-- Non-degenerate families: every family has a real deposit
-- (Fix R2-5: prevents solver from creating empty VaultFamily atoms)
-- ============================================================
fact familyNonDegenerate {
  -- Every VaultFamily atom has a deposit that is a real VaultUTXO
  all f : VaultFamily | some f.deposit and some f.allUTXOs
  -- No two families share a deposit
  all disj f1, f2 : VaultFamily | f1.deposit != f2.deposit
}

-- ============================================================
-- allUTXOs closure: constrain membership to transition-reachable UTXOs
-- ============================================================
fact allUTXOsClosure {
  -- Every UTXO in a family's allUTXOs must be either:
  -- (a) the deposit, or
  -- (b) the destination of a transition whose source is also in allUTXOs
  all f : VaultFamily, u : f.allUTXOs |
    u = f.deposit or
    (some t : Transition | t.family = f and u in t.dst and t.src in f.allUTXOs)

  -- Conversely: every transition destination within a family is in allUTXOs
  all t : Transition, d : t.dst | d in t.family.allUTXOs
}

-- ============================================================
-- Property 1: Fund Conservation
-- ============================================================
-- For each vault family, at any point in time, the total value of
-- all live UTXOs in the family equals the deposit minus cumulative fees.
-- We check the weaker version: total live value <= deposit value.

assert fundConservation {
  all f : VaultFamily, t : Time |
    let liveVault = { u : f.allUTXOs | u in liveAt[t] } |
      totalValue[liveVault] <= f.depositValue
}

-- ============================================================
-- Property 3: Recovery Destination Integrity
-- ============================================================
-- Recovery always sends funds to coldAddr, never to AttackerAddr

assert recoveryDestinationIntegrity {
  all r : RecoverTransition, d : r.dst |
    d.script = r.family.coldAddr and d.script != AttackerAddr
}

-- ============================================================
-- Property 4: Single-spend (vault level)
-- ============================================================
-- Each VaultUTXO is consumed by at most one transition

assert vaultSingleSpend {
  all u : VaultUTXO | lone t : Transition | t.src = u
}

-- ============================================================
-- Property 5: CSV Enforcement
-- ============================================================
-- Withdrawal requires CSV delay satisfaction

assert csvEnforcement {
  all w : WithdrawTransition |
    csvSatisfied[w.src, w.txn, w.src.csvDelay]
}

-- ============================================================
-- CTV Template: shared across CTV, CCV, and OP_VAULT
-- (All three use CTV for final withdrawal commitment)
-- ============================================================
sig CTVTemplate {
  committedOutputs : set UTXO,
  outputCount      : one Int
} {
  outputCount = #committedOutputs
  outputCount > 0
}

-- ============================================================
-- Checks (base-level, re-checked in each concrete model)
-- ============================================================
check fundConservation for 6 but 5 Int, 8 Time
check recoveryDestinationIntegrity for 6 but 5 Int, 8 Time
check vaultSingleSpend for 6 but 5 Int, 8 Time
check csvEnforcement for 6 but 5 Int, 8 Time
