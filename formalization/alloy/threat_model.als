/**
 * threat_model.als — Attacker Capabilities and Threat Scenarios
 *
 * Models different attacker profiles by specifying which keys the
 * attacker controls. Properties are checked under each attacker
 * profile to find the minimum capability needed for each attack.
 */
module threat_model

open btc_base
open vault_base

-- ============================================================
-- Concrete keys used across all vault designs
-- ============================================================
one sig HotKey extends Key {}          -- CTV: withdrawal signing
one sig ColdKey extends Key {}         -- CTV: recovery destination
one sig FeeKey extends Key {}          -- CTV: CPFP anchor spending
one sig UnvaultKey extends Key {}      -- CCV: trigger signing
one sig RecoverPubKey extends Key {}   -- CCV: recovery destination (not for signing)
one sig TriggerKey extends Key {}      -- OP_VAULT: trigger signing (xpub-derived)
one sig RecoveryAuthKey extends Key {} -- OP_VAULT: recovery authorization
one sig RecoveryDestKey extends Key {} -- OP_VAULT: recovery destination

-- ============================================================
-- Attacker: an entity trying to violate vault properties
-- ============================================================
one sig Attacker {
  controls : set Key    -- keys the attacker has compromised
}

-- ============================================================
-- Attacker profiles (predicates for scenario analysis)
-- ============================================================

-- No keys compromised (passive attacker / network observer)
pred noKeyAttacker {
  no Attacker.controls
}

-- CTV attack profiles
pred ctvHotKeyOnly {
  Attacker.controls = HotKey
}

pred ctvFeeKeyOnly {
  Attacker.controls = FeeKey
}

pred ctvHotAndFeeKey {
  Attacker.controls = HotKey + FeeKey
}

-- CCV attack profiles
pred ccvTriggerKeyOnly {
  Attacker.controls = UnvaultKey
}

pred ccvNoKey {
  no Attacker.controls
}

-- OP_VAULT attack profiles
pred opvTriggerKeyOnly {
  Attacker.controls = TriggerKey
}

pred opvRecoveryAuthOnly {
  Attacker.controls = RecoveryAuthKey
}

pred opvDualKey {
  Attacker.controls = TriggerKey + RecoveryAuthKey
}

-- ============================================================
-- Property 2: No Unauthorized Extraction
-- ============================================================
-- Funds cannot reach AttackerAddr unless attacker has sufficient keys
-- for the complete withdrawal path.

-- Generic: do any WITHDRAWN UTXOs end up at AttackerAddr?
pred fundsReachAttacker {
  some u : VaultUTXO |
    u.status = WITHDRAWN and u.script = AttackerAddr
}

-- The assertion: under the given attacker profile, funds should
-- not reach the attacker. Each concrete vault module checks this
-- with appropriate key constraints.

assert noUnauthorizedExtraction {
  -- If no key is compromised, funds never reach attacker.
  -- NOTE: This assertion relies on closing axioms in each concrete vault
  -- module to prevent orphan WITHDRAWN UTXOs. Without those axioms,
  -- Alloy can create WITHDRAWN UTXOs that bypass transition guards.
  noKeyAttacker implies not fundsReachAttacker
}

check noUnauthorizedExtraction for 6 but 5 Int, 8 Time

-- ============================================================
-- Liveness: can the owner always eventually withdraw?
-- ============================================================

-- There exists a path from VAULTED to WITHDRAWN
pred canWithdraw[f: VaultFamily] {
  some u : f.allUTXOs | u.status = WITHDRAWN and u.script = f.hotAddr
}

-- There exists a path from any state to RECOVERED
pred canRecover[f: VaultFamily] {
  all u : f.allUTXOs |
    (u.status in (VAULTED + UNVAULTING) and live[u]) implies
      some r : RecoverTransition | r.src = u
}
