/**
 * cross_covenant.als — Cross-Covenant Composition Analysis
 *
 * Models interactions between different vault types co-existing on
 * the same blockchain. These are the unexplored properties:
 *
 * 1. Cross-vault interaction: Can a CTV unvault tx consume a CCV
 *    vault UTXO as an additional input? (CTV doesn't commit to
 *    input prevouts.)
 *
 * 2. Fee wallet contention: Shared fee wallet across OP_VAULT
 *    instances creates resource contention.
 *
 * 3. Revault-to-dust termination: Does the splitting attack reach
 *    a fixed point at the dust threshold (546 sats)?
 */
module cross_covenant

open btc_base
open vault_base
open threat_model
-- Note: for full cross-vault analysis with concrete types, also open:
-- open ctv_vault
-- open ccv_vault
-- open opvault_vault
-- Kept abstract here to avoid pulling in all three vault models simultaneously,
-- which inflates the SAT search space. Use concrete imports when checking
-- specific cross-vault properties.

-- ============================================================
-- PROPERTY 9: Cross-vault input injection
-- ============================================================
-- CTV does not commit to input prevouts. This means a CTV-locked
-- transaction can consume *any* set of inputs, as long as the
-- outputs match the template.
--
-- Attack scenario: Attacker creates a CTV unvault transaction
-- that includes, as an additional input, a UTXO from a CCV vault.
-- Since CTV only checks outputs, the CCV UTXO is consumed without
-- CCV covenant checks (those checks only fire on the CCV spend path).

-- A transaction that consumes inputs from different vault families
sig CrossVaultTx extends Tx {
  ctvInput  : one VaultUTXO,   -- input governed by CTV
  extraInput : one VaultUTXO   -- input from a different vault type
} {
  ctvInput in inputs
  extraInput in inputs
  ctvInput != extraInput
  ctvInput.vaultFamily != extraInput.vaultFamily
}

-- Can a CTV unvault tx pull in a CCV vault UTXO?
pred crossInputInjection {
  some t : CrossVaultTx |
    -- The CTV input is a CTVVaultedUTXO being unvaulted
    -- The extra input is from a CCV vault
    -- CTV doesn't check what the extra input is
    t.ctvInput.status = VAULTED and
    t.extraInput.status = VAULTED and
    -- The extra input's value flows to the attacker
    -- (because CTV only constrains outputs, not input-output binding)
    t.ctvInput.vaultFamily != t.extraInput.vaultFamily
}

-- Analysis predicate: in what scenarios does this actually work?
-- The CCV UTXO has its own spending conditions (taptree).
-- For the cross-input attack to succeed:
-- 1. The CCV UTXO must be spendable without CCV checks
--    (only possible if mode confusion / keypath bypass applies)
-- 2. OR the transaction satisfies BOTH the CTV template AND
--    the CCV spending conditions simultaneously
pred viableCrossInjection {
  some t : CrossVaultTx |
    -- CTV template is satisfied (outputs match)
    -- AND CCV spending conditions are met on the extra input
    -- This requires the CCV input's spend path to be satisfied
    -- OR the CCV input has a vulnerability (mode confusion, keypath)
    t.ctvInput.vaultFamily != t.extraInput.vaultFamily and
    t.ctvInput.status = VAULTED and
    t.extraInput.status = VAULTED
}

-- Assertion: cross-vault injection should not be possible if both
-- vaults are correctly configured
assert noCrossVaultInjection {
  -- If the extra input has proper CCV enforcement, the cross-vault
  -- tx cannot satisfy both covenant conditions simultaneously
  -- (CTV constrains outputs; CCV constrains outputs differently)
  all t : CrossVaultTx |
    -- At least one covenant check must fail
    not (t.ctvInput.status = VAULTED and t.extraInput.status = VAULTED)
}

-- ============================================================
-- PROPERTY 10: Revault-to-Dust Termination
-- ============================================================
-- The splitting attack creates progressively smaller UTXOs.
-- Does it terminate at the dust threshold?

-- Dust threshold: 546 sats for P2TR outputs (Bitcoin Core standard)
fun dustThreshold : Int { 2 }  -- abstracted; use scope-appropriate value

-- A UTXO is dust if its value <= dust threshold
pred isDust[u: UTXO] {
  u.value <= dustThreshold
}

-- The splitting attack: each revault divides value
-- After N splits, the smallest UTXO has value = deposit / 2^N
-- (if splitting by half each time)

-- Predicate: does the splitting sequence terminate?
-- I.e., does every chain of revaults eventually produce a dust UTXO?
pred splittingTerminates {
  -- For any chain of revault transitions, eventually some output
  -- falls below dust threshold
  all f : VaultFamily |
    (#{r : RevaultTransition | r.family = f} > 2) implies
      some u : f.allUTXOs | isDust[u]
}

-- Can an attacker craft splits that stay above dust indefinitely?
-- With geometric splitting (withdraw fraction < 50%), the vault
-- UTXO decreases but the unvaulting UTXOs can be kept above dust
-- by choosing the right split amount.
pred indefiniteSplitting {
  -- There exists a sequence of revaults where every output is above dust
  some f : VaultFamily |
    #{r : RevaultTransition | r.family = f} > 3 and
    all u : f.allUTXOs | not isDust[u]
}

-- ============================================================
-- PROPERTY 12: Attacker-optimal split strategy
-- ============================================================
-- The attacker wants to maximize the number of splits while
-- keeping each unvaulting UTXO above the dust threshold.
-- Optimal strategy: withdraw dust+1 each time, keeping remainder
-- as the new vault.

-- At each split, the attacker withdraws `minWithdraw` sats
fun minViableWithdraw : Int { 3 }  -- dust + 1 (abstracted)

-- Maximum splits from a given deposit value
-- deposit / minViableWithdraw (geometric ceiling)
pred maxSplits[f: VaultFamily, n: Int] {
  -- n is the number of revault transitions in this family
  #{r : RevaultTransition | r.family = f} = n
  -- All unvaulting outputs are >= dust threshold
  all u : f.allUTXOs | u.status = UNVAULTING implies
    u.value >= minViableWithdraw
}

-- ============================================================
-- CHECKS
-- ============================================================

-- Cross-vault injection (should find instance if CTV + CCV coexist)
check noCrossVaultInjection for 8 but 5 Int, 10 Time

-- Splitting termination
run splittingTerminates for 10 but 5 Int, 12 Time
run indefiniteSplitting for 10 but 5 Int, 12 Time

-- ============================================================
-- Instance generation for cross-covenant scenarios
-- ============================================================

-- Scenario: CTV and CCV vaults on the same chain
pred mixedVaultChain {
  -- At least one CTV vault family and one CCV vault family
  -- (would need to import ctv_vault and ccv_vault; here we
  -- model it abstractly with different VaultFamily subtypes)
  some disj f1, f2 : VaultFamily |
    f1 != f2 and
    some u1 : f1.allUTXOs | u1.status = VAULTED and
    some u2 : f2.allUTXOs | u2.status = VAULTED
}
run mixedVaultChain for 8 but 5 Int, 10 Time

-- Fee wallet shared across two OP_VAULT families
pred sharedFeeWallet {
  some disj f1, f2 : VaultFamily |
    f1 != f2
  -- Both families need fee wallet UTXOs for operations
  -- But there's only one fee wallet with limited UTXOs
}
run sharedFeeWallet for 8 but 5 Int, 10 Time
