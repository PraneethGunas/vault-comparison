/**
 * btc_base.als — Bitcoin UTXO Model for Covenant Vault Verification
 *
 * Models the Bitcoin transaction graph at the level needed for covenant
 * analysis: UTXOs as atoms with value/script, transactions as consumers
 * and producers of UTXOs, and keys as abstract capabilities.
 *
 * Design decisions:
 *   - Values are abstract (Int with bounded scope), not exact satoshi counts.
 *     Alloy's bounded integers suffice for conservation checks; exact arithmetic
 *     requires different tooling.
 *   - Time is modeled as a total order on transactions (the blockchain), not
 *     as real-valued timestamps. CSV is a relative ordering constraint.
 *   - The UTXO graph is explicit: each UTXO is created by exactly one tx
 *     and consumed by at most one tx. Double-spend is a structural violation
 *     of this uniqueness.
 *
 * Author: Praneeth / formal model for vault comparison framework
 */
module btc_base

open util/ordering[Time] as TimeOrd

-- ============================================================
-- Time: abstract block height / ordering of confirmation
-- ============================================================
sig Time {}

-- ============================================================
-- Keys and Addresses
-- ============================================================

abstract sig Key {}

-- An address is a destination for funds. Addresses derived from
-- keys are spendable; covenant-locked addresses require script
-- satisfaction.
abstract sig Address {
  owner : lone Key   -- who can ultimately spend from here (if anyone)
}

-- Concrete address types
sig P2WPKHAddr extends Address {}  -- standard pay-to-witness-pubkey-hash
sig P2WSHAddr extends Address {}   -- pay-to-witness-script-hash
sig P2TRAddr extends Address {}    -- pay-to-taproot

-- Special: attacker-controlled address
one sig AttackerAddr extends Address {}

-- ============================================================
-- UTXO: the fundamental unit of Bitcoin state
-- ============================================================
sig UTXO {
  value    : Int,          -- abstract satoshi value (positive)
  script   : Address,      -- locking script / destination
  created  : one Tx,       -- transaction that created this UTXO
  spent    : lone Tx,      -- transaction that consumed it (at most one)
  spentAt  : lone Time     -- confirmation time of spending tx
} {
  value > 0                    -- no zero-value UTXOs (dust threshold abstracted)
  created != spent             -- a tx cannot spend its own output in same tx
  some spent implies some spentAt
  no spent implies no spentAt
}

-- A UTXO is "live" if it has not been spent
pred live[u: UTXO] {
  no u.spent
}

-- A UTXO is "confirmed" at time t if its creating tx is at or before t
pred confirmed[u: UTXO, t: Time] {
  some u.created.confirmTime and lte[u.created.confirmTime, t]
}

-- ============================================================
-- Transactions
-- ============================================================
sig Tx {
  inputs      : set UTXO,      -- consumed UTXOs
  outputs     : set UTXO,      -- created UTXOs
  confirmTime : lone Time,     -- when confirmed (lone: maybe unconfirmed)
  signers     : set Key         -- keys that signed this transaction
} {
  some inputs                    -- at least one input
  some outputs                   -- at least one output (coinbase aside)
  -- Every input UTXO must record this tx as its spender
  all u : inputs | u.spent = this
  -- Every output UTXO must record this tx as its creator
  all u : outputs | u.created = this
}

-- ============================================================
-- Coinbase: the initial funding source
-- ============================================================
sig CoinbaseTx extends Tx {} {
  -- Coinbase has no real inputs; we model it with a self-referential
  -- dummy. In practice we just allow coinbase outputs to exist.
  no signers
}

-- ============================================================
-- Fee: value conservation with fee extraction
-- ============================================================

-- The fee is the difference between input value and output value.
-- For Alloy's bounded integers we check: sum(inputs.value) >= sum(outputs.value)
-- The "fee" is the remainder consumed by the miner.
pred validFee[t: Tx] {
  (sum i : t.inputs | i.value) >= (sum o : t.outputs | o.value)
}

-- Strict conservation (no fee): used for checking fund conservation
-- invariant where we abstract away fees
pred strictConservation[t: Tx] {
  (sum i : t.inputs | i.value) = (sum o : t.outputs | o.value)
}

-- ============================================================
-- UTXO graph well-formedness
-- ============================================================
fact utxoGraphWellFormed {
  -- Each UTXO is created by exactly one tx (structural from sig)
  -- Each UTXO is spent by at most one tx (structural from sig)

  -- No UTXO appears in both inputs and outputs of the same tx
  all t : Tx | no (t.inputs & t.outputs)

  -- Outputs of different transactions are disjoint
  all disj t1, t2 : Tx | no (t1.outputs & t2.outputs)

  -- If a UTXO is in tx's inputs, that UTXO must have been created
  -- by a transaction confirmed before tx
  all t : Tx, u : t.inputs |
    some t.confirmTime and some u.created.confirmTime implies
      lt[u.created.confirmTime, t.confirmTime]

  -- Every transaction has a valid fee (inputs >= outputs)
  all t : Tx - CoinbaseTx | validFee[t]
}

-- No cycles in the transaction graph
fact noCycles {
  all t : Tx | t not in t.^(outputs.spent)
}

-- ============================================================
-- CSV (CheckSequenceVerify): relative timelock
-- ============================================================

-- csvSatisfied[u, t, delay]: UTXO u was created at least `delay`
-- time steps before transaction t confirms.
-- We model this using the ordering on Time: the set of Time atoms
-- strictly between createTime and spendTime must have at least
-- (delay - 1) elements (i.e., spendTime is at least delay steps after createTime).
pred csvSatisfied[u: UTXO, t: Tx, delay: Int] {
  some u.created.confirmTime and some t.confirmTime and
  delay > 0 and
  let createTime = u.created.confirmTime,
      spendTime  = t.confirmTime |
    -- spendTime must be strictly after createTime
    lt[createTime, spendTime] and
    -- The number of Time atoms from createTime up to (not including) spendTime
    -- must be >= delay. We count atoms in the half-open interval [createTime, spendTime).
    #{t0 : Time | gte[t0, createTime] and lt[t0, spendTime]} >= delay
}

-- ============================================================
-- Single-spend property (should be structural but we assert it)
-- ============================================================
assert singleSpend {
  all u : UTXO | lone u.spent
}

-- This is enforced by the `lone` declaration on spent, but
-- we assert it explicitly for clarity and as a sanity check.
check singleSpend for 8 but 6 Int, 10 Time

-- ============================================================
-- Utility predicates
-- ============================================================

-- Total value held by a set of UTXOs
fun totalValue[utxos: set UTXO] : Int {
  sum u : utxos | u.value
}

-- All live UTXOs at a given time
fun liveAt[t: Time] : set UTXO {
  { u : UTXO | some u.created.confirmTime and
                lte[u.created.confirmTime, t] and
                (no u.spent or gt[u.spentAt, t]) }
}
