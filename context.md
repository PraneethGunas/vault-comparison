# Vault Comparison Framework — Context

This document covers the architecture, design rationale, and experiment catalog for the vault comparison framework.

## 1. Purpose

This framework exists to produce reproducible, quantitative comparisons between Bitcoin vault covenant designs. It currently targets three implementations:

1. CTV vault (`simple-ctv-vault`) — OP_CHECKTEMPLATEVERIFY (BIP 119) single-hop vault
2. CCV vault (`pymatt`) — OP_CHECKCONTRACTVERIFY (BIP 443) + CTV full vault
3. OP_VAULT vault (`simple-op-vault` / opvault-demo) — OP_VAULT + OP_VAULT_RECOVER (BIP 345) + CTV

The goal is to separate design-level tradeoffs from implementation-level bugs, and to measure concrete costs (vsize, fees, key requirements, attack surfaces) rather than relying on qualitative comparisons alone.

### 1.1 Prior Art and Contribution Scope

This work builds on a body of prior research in covenant-based vault custody. The full attribution mapping is in [`REFERENCES.md`](../REFERENCES.md).

**What is NOT new (prior art we build on):**

The vault lifecycle model and threat vocabulary follow Swambo et al. ([arXiv 2005.11776](https://arxiv.org/abs/2005.11776)), which formalized the deposit→unvault→withdraw structure, the watchtower monitoring assumption, and the fundamental tension between pre-committed transaction trees (CTV-style) and reactive covenant enforcement (OP_VAULT-style). Finding #4 (CTV immune to watchtower exhaustion but inflexible) restates their static-vs-dynamic vault distinction. The keyless recovery griefing vector (finding #2) was identified qualitatively by Ingala ([BIP-443](https://bips.dev/443/)) on the bitcoin-dev mailing list. The TRUC/v3 mitigation for descendant pinning (finding #1) is documented in Bitcoin Core PRs [#28948](https://github.com/bitcoin/bitcoin/pull/28948), [#29496](https://github.com/bitcoin/bitcoin/pull/29496). The authorized-recovery tradeoff in OP_VAULT was analyzed by O'Beirne and Sanders ([BIP-345](https://bips.dev/345/)). Harding's watchtower fee exhaustion analysis ([Delving Bitcoin](https://delvingbitcoin.org/t/op-vault-comments/521)) estimated ~3,000 chunks/block and ~0.3 BTC watchtower reserve. The CCV mode confusion risk with undefined flags was discussed by Ingala as a known OP_SUCCESS design decision. We did not discover these vulnerabilities — they were identified in design-review contexts during 2020–2024.

**What IS new (our contribution is measurement and synthesis, not discovery):**

The conceptual contribution is a *unified measurement framework* that reveals how design-level tradeoffs compose under realistic fee environments. Specifically:

1. **The first three-way empirical comparison.** Regtest-measured transaction sizes for CTV, CCV, and OP_VAULT under a uniform adapter interface (12 experiments, 7 threat models). Prior analysis compared at most two designs, or used estimates rather than measured values. The OP_VAULT vsize measurements reveal the fee-input overhead: all non-deposit transactions are 80–90 vB larger than expected (§4.2), making OP_VAULT's lifecycle 36% more expensive than CCV's.

2. **Fee-dependent inversion of security rankings.** The cross-experiment fee sensitivity synthesis (experiment J) shows that the *relative* security ordering of vault designs flips depending on fee environment. In low-fee regimes (1–10 sat/vB), CCV and OP_VAULT are safer than CTV (fee pinning is cheap but splitting is infeasible). In high-fee regimes (100–500 sat/vB), watchtower exhaustion becomes feasible against CCV/OP_VAULT while CTV's fee pinning cost remains negligible — the security ordering inverts. This fee-dependent crossover is the strongest finding: no prior analysis has shown that the answer to "which vault is safest?" depends on the fee environment.

3. **The inverse-ranking structural result.** Griefing resistance and fund safety under key loss are anti-correlated across all three designs: OP_VAULT > CTV > CCV for griefing resistance, CCV > CTV > OP_VAULT for key-loss safety. This is a necessary tradeoff (not an implementation artifact): blocking unauthorized recovery *requires* a key whose loss disables recovery. Any vault design must choose a position on this axis.

4. **Empirical confirmation/correction of prior estimates.** Harding's ~3,000 chunks/block estimate is confirmed (measured: 3,427 CCV, structural). OP_VAULT hand-estimated vsizes were significantly wrong (trigger: 200→292, recovery: 170→246) due to the 2-input fee-wallet pattern. The CCV mode confusion result with undefined flags is an empirical demonstration, though closer to a bug report than a research contribution.

The per-experiment relationship to prior work is detailed in `REFERENCES.md` §2.

## 2. Protocol Background

This section summarizes the three covenant opcodes and their vault constructions. Each subsection covers what the opcode commits to, what it does not, and how the vault lifecycle maps onto it.

### 2.1 OP_CHECKTEMPLATEVERIFY (CTV / BIP 119)

CTV constrains the structure of the transaction that spends a UTXO. A script of the form `<hash> OP_CHECKTEMPLATEVERIFY` requires the spending transaction to match a standard template hash that commits to: `nVersion`, `nLockTime`, `scriptSigs` hash (if non-empty), input count, `nSequence` hash, output count, outputs hash (amounts + scriptPubKeys), and `spend_index`.

CTV does **not** commit to input prevouts (which UTXOs are being spent), input amounts, or witness data. This means CTV constrains *what* a transaction does but not *which* UTXOs it consumes — the root cause of the address-reuse vulnerability.

**CTV vault lifecycle** (`simple-ctv-vault`):

```
Original UTXO
    │
    ▼
tovault_tx ──── Bare CTV script: <H(unvault_tx)> OP_CTV
    │
    ▼
unvault_tx ──── P2WSH with IF/ELSE:
    │               IF:   <block_delay> OP_CSV, <hot_pk> OP_CHECKSIG
    │               ELSE: <H(tocold_tx)> OP_CTV
    │
    ├──▶ tohot_tx   ── After block_delay, signed with hot key → P2WPKH(hot)
    │
    └──▶ tocold_tx  ── Immediate CTV sweep → P2WPKH(cold)
```

Key properties: the tovault→unvault step requires no signature (CTV-only encumbrance). The cold sweep (tocold) is also CTV-only and immediate. The hot spend (tohot) requires `block_delay` blocks plus a hot key signature. Both tohot and tocold have an anchor output at `vout=1` (550 sats) for CPFP fee bumping. The entire transaction tree is deterministic and can be regenerated from key material plus the original coin — no presigned transaction storage needed.

**Known CTV-only limitations:**

1. **Address reuse** — CTV commits to exact output amounts derived from the original deposit. A second deposit of a different amount creates a permanently unspendable UTXO (or massively overpays miners if larger).
2. **Staged funds theft** — The unvault tx requires no signature, so anyone with the hot key can complete the withdrawal after the timelock expires.
3. **Fee management fragility** — Anchor-based CPFP is the only fee-bumping mechanism. Descendant-chain pinning defeats it.
4. **No key rotation** — Keys baked into CTV hashes cannot be rotated without destroying and recreating the vault.

### 2.2 OP_CHECKCONTRACTVERIFY (CCV / BIP 443)

CCV is a covenant opcode that enforces relationships between transaction inputs/outputs and Taproot contract structure. High-level stack form:

```
<data> <index> <pk> <taptree> <mode> OP_CHECKCONTRACTVERIFY
```

Where `data` is optional state bytes (embedded via tweak), `index` is the output/input index to validate, `pk` is the expected internal key (or sentinel), `taptree` is the expected script tree root (or sentinel), and `mode` is the checking mode (check output, deduct output amount, check input, etc.). This lets contracts enforce deterministic state transitions without pre-signing a full transaction tree.

**CCV vault lifecycle** (`pymatt`):

The full vault uses both CCV (for state transitions) and CTV (for the final withdrawal template):

```
Funded Vault UTXO
    │
    │ trigger / trigger_and_revault
    ▼
Unvaulting UTXO (state contains ctv_hash)
    │
    │ wait spend_delay (CSV)
    ▼
Withdraw transaction constrained by CTV template

Emergency path:
Vault or Unvaulting → recover to recover_pk (keyless)
```

The trigger step stores a `ctv_hash` into the contract state via CCV. The withdraw path checks the CSV timelock and executes `OP_CHECKTEMPLATEVERIFY` against the stored hash. A minivault variant (`minivault_contracts.py`) uses CCV only — no CTV — with the withdraw path sending to a single P2TR destination via CCV checks.

**CCV-specific capabilities:** partial withdrawal via `trigger_and_revault` (splits the vault into an unvaulting UTXO and a re-funded vault), batched triggers across multiple vault UTXOs in a single transaction, and keyless recovery (anyone can invoke the recover clause without a signature).

**CCV-specific risks:** undefined mode values (4, 7, 128, 255) trigger OP_SUCCESS — script succeeds unconditionally with no covenant enforcement. This enables clean soft-fork upgrades but creates a silent failure mode for developers. Keypath bypass is possible if a developer passes a real public key instead of a NUMS point as `alternate_pk`. Sentinel confusion (-1 vs 0) can cause clauses to skip checks or fail unexpectedly.

### 2.3 OP_VAULT + OP_VAULT_RECOVER (BIP 345)

OP_VAULT is a purpose-built vault opcode pair. `OP_VAULT` constrains how a vault UTXO can be spent (trigger a withdrawal with a CTV-locked destination), and `OP_VAULT_RECOVER` enables authorized recovery to a pre-committed recovery address. Unlike CCV's keyless recovery, the default OP_VAULT configuration requires a `recoveryauth` key signature to invoke recovery — this is a deliberate anti-griefing design choice.

**OP_VAULT lifecycle** (`simple-op-vault` / opvault-demo):

```
Deposit UTXO
    │
    │ start_withdrawal() — Schnorr-signed trigger + CTV-locked withdrawal pair
    ▼
Trigger TX → Unvaulting UTXO (CTV template committed)
    │         + optional revault UTXO (partial withdrawal)
    │
    │ wait spend_delay (CSV)
    ▼
Withdrawal TX — broadcast CTV template

Emergency path:
Vault or Unvaulting → get_recovery_tx() (authorized with recoveryauth key)
```

**OP_VAULT-specific capabilities:** automatic partial withdrawal when withdrawal amount < vault balance (the `start_withdrawal()` function handles the split), batched triggers across multiple vault UTXOs, and authorized recovery (requires the recoveryauth key, preventing fee-griefing by arbitrary third parties).

**OP_VAULT-specific limitations:** authorized recovery means the recoveryauth key is a single point of failure — its compromise enables an attacker to recover funds to the pre-committed recovery address (which the legitimate owner controls, so this is a liveness attack, not a theft vector). The implementation depends on `verystable` library with known API instability (`.nVersion` vs `.version`, `script=` vs `leaf_script=` parameter renames).

## 3. Architecture

### 3.1 Adapter Pattern

The core abstraction is `VaultAdapter` (in `adapters/base.py`), an abstract base class that wraps each vault implementation behind a uniform interface:

```
VaultAdapter
├── create_vault(amount_sats) → VaultState
├── trigger_unvault(vault) → UnvaultState
├── complete_withdrawal(unvault) → TxRecord
├── recover(state) → TxRecord
├── supports_revault() → bool
├── supports_batched_trigger() → bool
├── supports_keyless_recovery() → bool
├── trigger_revault(vault, amount) → (UnvaultState, VaultState)
├── trigger_batched(vaults) → UnvaultState
└── collect_tx_metrics(record, rpc) → TxMetrics
```

Each adapter lazy-loads its vault implementation at `setup()` time, avoiding import-time dependencies on either codebase.

### 3.2 Data Types

- `VaultState` — opaque handle for a funded vault. Carries txid, amount, and adapter-specific `extra` dict.
- `UnvaultState` — handle for an unvaulting UTXO. Carries txid, amount, blocks remaining, and `extra`.
- `TxRecord` — broadcast transaction receipt. Carries txid, label, raw hex, and amount.
- `TxMetrics` — per-transaction measurements: vsize, weight, fee, input/output counts, script type, CSV blocks.
- `ExperimentResult` — collects all observations, tx metrics, and errors for one experiment run on one covenant.
- `ComparisonResult` — pairs results from two covenants for the same experiment.

### 3.3 Experiment Registry

Experiments are discovered via the `@register` decorator in `experiments/registry.py`. Each experiment module defines a `run(adapter: VaultAdapter) -> ExperimentResult` function decorated with `@register(name=..., description=..., tags=[...])`.

Tags enable selective execution (e.g., `--tag core` runs all foundational experiments).

### 3.3.1 Experiment Categories (Tag Taxonomy)

Experiments are classified along two orthogonal axes: **scope** (which covenants the experiment meaningfully runs on) and **concern** (what the experiment measures).

**Scope tags:**
- `comparative` — True head-to-head comparison. Runs the same test on both CTV and CCV, and the finding comes from the difference in outcomes. (lifecycle_costs, address_reuse, fee_pinning, recovery_griefing)
- `capability_gap` — Demonstrates a capability CCV has that CTV lacks. Runs on both, but CTV reports "unsupported" while CCV demonstrates the feature and measures its cost. (multi_input, revault_amplification)
- `ccv_only` — Only runs on CCV. Tests CCV-specific semantics or developer footguns with no CTV analog. (ccv_edge_cases)

There are currently no CTV-only experiments. CTV's weaknesses (stuck funds, fee pinning, no partial withdrawal) surface naturally within the comparative experiments.

**Concern tags:**
- `quantitative` — Collects TxMetrics (vsize, weight, fee). Not every experiment needs cost metrics; only those where cost is part of the finding. (lifecycle_costs, multi_input, revault_amplification, recovery_griefing)
- `security` — Probes attack surfaces, blast radii, or exploit conditions. (fee_pinning, recovery_griefing, ccv_edge_cases, address_reuse, watchtower_exhaustion)

**Cost measurement rationale:** `lifecycle_costs` is the dedicated cost baseline — it measures the standard deposit→unvault→withdraw path on both covenants. Other experiments collect cost metrics only when cost is *part of the specific finding* (e.g., revault_amplification measures how costs accumulate across chained partial withdrawals; multi_input measures batching savings). Experiments like address_reuse and fee_pinning are behavioral — their findings are about stuck funds and pinning surfaces, not vsize. Bolting cost metrics onto every experiment would add noise without adding signal.

### 3.4 Reporting

`harness/report.py` saves results to `results/<timestamp>_<experiment>/`:
- `<covenant>.json` — raw result data
- `comparison.md` — side-by-side markdown table (if both covenants were tested)

### 3.5 Threat Model Methodology

Each security-tagged experiment defines a structured threat model for every attack it analyzes. The format is designed for a conference reviewer who expects precision about adversary capabilities, not just "attacker does X."

**Standard threat model fields:**

- **Attacker** — What the adversary has and can do. Specifies required capabilities (key material, mempool access, hashrate, network position) and what they explicitly do *not* have. The minimum viable attacker — the weakest adversary who can still mount the attack.
- **Goal** — What constitutes success for the attacker. Precise and measurable: "extract N sats from the vault" or "deny liveness for M blocks," not "compromise the vault."
- **Attack cost** — What the attacker spends to mount the attack. Includes on-chain fees (transaction vsize × fee rate), opportunity cost of locked capital, and any off-chain costs (maintaining mempool observation, running a node, etc.). Expressed in sats where possible.
- **Payoff** — What the attacker gains on success. Expressed in sats or as a function of vault balance. Identifies whether the payoff scales with vault size.
- **Rationality condition** — Under what conditions is the attack economically worth mounting? Payoff > cost is necessary but not sufficient — the attack must also be more profitable than the attacker's next-best alternative (e.g., honest mining). Identifies the breakeven point.
- **Defender response** — What the vault owner can do, at what cost, and within what time window. Includes the defender's detection requirements (watchtower, mempool monitoring, etc.).
- **Residual risk** — What remains even after the defender responds optimally. "Funds safe but N sats spent on recovery fees" is a different outcome from "no impact."

**When threat models are omitted:** Purely quantitative experiments (lifecycle_costs) and capability-gap experiments (multi_input, revault_amplification) don't define adversaries because their findings are about cost efficiency, not security. The cost data from these experiments *feeds into* the economic rationality analysis of the security experiments — for instance, the cost of mounting a forced-recovery griefing attack depends on the recovery transaction vsize measured in lifecycle_costs.

### 3.6 Regtest Limitations (External Validity)

All experiments run on Bitcoin Core regtest.  This is a deliberate methodological choice — regtest provides deterministic, reproducible execution without external dependencies — but it limits external validity in four specific ways:

**(1) No mempool competition.**  Regtest mines every transaction immediately (or on demand with `generatetoaddress`).  Attacks that depend on mempool dynamics — fee pinning, front-running via mempool observation, recovery races against timelocks — lose their temporal realism.  On mainnet, a recovery transaction must confirm before the CSV timelock expires, competing against all other pending transactions for block space.

**(2) No relay policy pressure.**  Bitcoin Core's relay policy (minimum relay fee ≈ 1 sat/vB, ancestor/descendant limits at 25 txs / 101 kvB, RBF rules, TRUC/v3 transaction semantics) constrains transaction propagation on mainnet.  Regtest enforces these limits in its mempool but the absence of competing traffic means the constraints are never stressed.  The fee pinning attack depends entirely on relay policy details; the descendant chain limit is tested but not under adversarial pressure.

**(3) No fee market.**  Transaction fees on regtest are arbitrary — miners accept anything above the dust relay threshold.  The fee amounts reported by experiments are whatever the adapter's coin selection happened to set, NOT what a rational miner would demand.  **The vsize measurements are the structurally valid metric; fee amounts in sats are artifacts.**

**(4) Mining is instant.**  The `block_delay` / `spend_delay` parameter (e.g. 10 blocks ≈ 100 minutes on mainnet) resolves in milliseconds on regtest.  Time-critical attacks — the defender's recovery race, the attacker's sustained splitting, the griefing loop — lose all temporal realism.

**Methodology response:**  We treat **vsize as the primary metric** and compute fees as `vsize × fee_rate`, where `fee_rate` is an exogenous parameter.  Every security experiment emits a fee sensitivity table (via `harness/regtest_caveats.py`) showing how the threat model's rationality condition shifts across 1, 10, 50, 100, 300, and 500 sat/vB.  This separates what we CAN measure on regtest (structural transaction costs, script behavior, witness structure) from what we CANNOT (fee market dynamics, mempool competition, temporal races).

**What IS valid on regtest:**

- Transaction vsize and weight (structural, deterministic)
- Witness structure and script execution semantics (e.g. OP_SUCCESS for undefined CCV flags)
- Descendant chain limits and mempool policy rules (enforced identically)
- Contract state transitions (vault → unvault → withdraw/recover)
- Cost asymmetries between transaction types (trigger vs recovery vsize)

**What is NOT valid:**

- Absolute fee amounts in sats (artifacts of regtest coin selection)
- Timing of recovery races (instant mining eliminates real-world latency)
- Mempool front-running dynamics (no competing traffic)
- Fee market pressure on transaction confirmation

**Per-experiment impact:**

| Experiment | Regtest validity | Primary limitation |
|---|---|---|
| lifecycle_costs | vsize fully valid | Fee amounts are artifacts |
| address_reuse | Fully valid (structural behavior) | N/A |
| fee_pinning | Descendant chain limits valid; pinning race untested | No competing traffic to contest pinning |
| recovery_griefing | vsize asymmetry valid; front-running untested | Mempool race is argued, not demonstrated |
| multi_input | vsize/weight scaling fully valid | Fee amounts are artifacts |
| revault_amplification | vsize/weight fully valid | Fee amounts are artifacts |
| ccv_edge_cases | Fully valid (consensus-level script semantics) | N/A — OP_SUCCESS is not relay-dependent |
| watchtower_exhaustion | vsize and economic model valid; recovery race untested | Temporal dynamics of sustained splitting |
| fee_sensitivity | Fully valid (analytical, uses structural vsize) | N/A — does not produce on-chain transactions |

### 3.7 Fee Environment Sensitivity Analysis

The fee sensitivity analysis (§J in the experiment catalog) synthesizes vsize measurements from ALL experiments and projects them into real-world economic costs at historically observed fee rates: 1 sat/vB (2021 low), 10 sat/vB (2022 average), 50 sat/vB (2023 moderate), 100 sat/vB (2024 inscriptions), 300 sat/vB (2023 BRC-20 spike), and 500 sat/vB (stress scenario).

**Key findings:**

1. **Fee pinning is fee-invariant in severity.** The attack costs <0.5% of vault value at any historical fee rate (breakeven at ~19,000 sat/vB, never observed). Combined with hot-key theft, this is CTV's worst-case failure mode under current relay policy. Note: the TRUC/v3 transaction proposal would eliminate descendant-chain pinning if adopted, narrowing this attack surface.

2. **Recovery griefing scales linearly but remains cheap.** At 500 sat/vB, 10 rounds of CCV keyless griefing costs the attacker ~610,000 sats (~1.2% of a 0.5 BTC vault). High fees deter griefing but don't eliminate it.

3. **Watchtower exhaustion has a fee-dependent crossover.** At 1 sat/vB, exhaustion requires ~410k splits (infeasible). At 300 sat/vB, ~1,366 splits (feasible with sustained attack). High-fee environments make this attack MORE viable, not less — the opposite of griefing.

4. **CTV and CCV have complementary vulnerability profiles.** CTV's worst case (fee pinning + hot key compromise) is fee-invariant; CCV's worst case (watchtower exhaustion) is fee-dependent. Both have mitigations outside the current protocol: CTV benefits from TRUC/v3 transactions (eliminating descendant-chain pinning) and standard address hygiene (preventing reuse). CCV benefits from batched recovery (extending watchtower viability) and potential future anti-griefing mechanisms. Which failure mode is more operationally severe depends on deployment context.

The full analysis with tables, charts, and crossover analysis is generated by `experiments/exp_fee_sensitivity.py` and can be run standalone via `python3 run_fee_analysis.py`.

## 4. Experiment Catalog

### A. lifecycle_costs [comparative, quantitative]
Measures the full deposit → unvault → withdrawal lifecycle. Collects vsize, weight, and fee for each transaction step. This is the cost baseline for all other experiments.

### B. address_reuse [comparative, security]
Tests what happens when a second deposit hits the same vault address. CTV: permanently stuck or massively overpays miners. CCV: safe — each funding creates an independent contract instance.

**Threat model — accidental reuse (user error):**
- Attacker: None (self-inflicted). The "adversary" is the user's own wallet software or an exchange that reuses a deposit address.
- Goal: N/A — this is a design-level footgun, not an adversarial attack.
- Cost to victim: The full amount of the second deposit (permanently unspendable on CTV).
- Rationality: Always relevant. Address reuse is common in Bitcoin wallet software and exchange deposit workflows. Any vault design deployed at scale will encounter this.
- Defender response (CTV): Prevention only — wallet software must enforce single-use address discipline (standard Bitcoin hygiene, but not universally followed in practice). No recovery path if reuse occurs.
- Defender response (CCV): No action needed. Each deposit is independently spendable.
- Residual risk (CTV): Total loss of reused deposit, mitigable by wallet-layer enforcement. Residual risk (CCV): None.

### C. fee_pinning [comparative, security]
Empirically demonstrates descendant-chain pinning on CTV's tocold anchor output. Phase 1 confirms anchor presence. Phase 2 (CTV) builds an actual descendant chain from the anchor using the fee key, verifies the mempool descendant limit is reached, then has the defender attempt CPFP via the cold key on the main output (vout[0]) — which is rejected (too-long-mempool-chain), proving all CPFP paths are blocked. Phase 2 (CCV) confirms no anchor outputs exist. Phase 3 computes attack economics across fee rates.

**Threat model — descendant-chain pinning (CTV):**
- Attacker: Has the fee key (compromised) OR the anchor is anyone-can-spend (P2WSH(OP_TRUE)). Can observe the mempool and broadcast transactions. No hashrate required.
- Goal: Block CPFP fee bumping on the cold sweep transaction (tocold) for at least `block_delay` blocks, preventing the defender from completing recovery before the hot withdrawal timelock expires.
- Attack cost: 25 small transactions spending from the anchor output chain. At minimum relay fee (1 sat/vB), each ~110 vbytes = ~110 sats. Total: ~2,750 sats in fees, plus 25 × 546 sats dust outputs = ~16,400 sats total capital deployed. Trivial relative to any meaningful vault balance.
- Payoff: Enables the hot-key theft path. Payoff = vault balance (up to full amount).
- Rationality condition: Rational whenever vault balance > ~20,000 sats (breakeven). In practice, any vault worth using has a balance orders of magnitude above this threshold. The attack is overwhelmingly rational for an attacker who already has the fee key.
- Defender response: None within the CTV vault design. The fee key is baked into the CTV template hash at vault creation time; it cannot be rotated. External mitigations: use a separate fee-bumping mechanism (e.g., package relay / TRUC transactions if available), or detect the pinning and use an alternative broadcast path.
- Residual risk: If the attacker also has the hot key, this enables full fund theft with no defense. Fee pinning alone denies liveness but doesn't steal funds.

### D. revault_amplification [capability_gap, quantitative]
Tests partial-withdrawal chaining. CTV: not supported natively — reports unsupported, shows fallback cost. CCV: native revault via `trigger_and_revault`, chainable N times with diminishing remainder. Collects per-step cost metrics.

No adversarial threat model — this is a cost-efficiency experiment. The data feeds into the economic rationality of recovery_griefing (defender's cost to repeatedly recover after forced re-vaults).

### E. multi_input [capability_gap, quantitative]
Sweeps batched trigger across vault counts [1, 2, 3, 5, 10, 20, 50] to characterize the scaling curve at institutional scale. CTV: impossible (CTV commits to input count per template), so costs are N × single_trigger. CCV: supported, with real batched trigger measurements and per-vault marginal cost regression. Includes ceiling analysis projecting when tx weight hits standardness (400k WU) and block (4M WU) limits. Annotates the cross-input DEDUCT accounting footgun with safe/unsafe coordinator patterns.

No adversarial threat model — this is a cost-efficiency experiment. The DEDUCT footgun is a developer error, not an adversarial attack (see §3.5 on when threat models are omitted).

### F. recovery_griefing [comparative, security, quantitative]
Measures the asymmetric cost of forced-recovery griefing attacks on both covenant designs. The attacker–defender asymmetry has three components: (1) trigger vsize > recovery vsize, (2) defender bears opportunity cost of delayed withdrawal, (3) attacker has mempool front-running advantage. Runs a multi-round griefing loop measuring cumulative costs, then analyzes fee-rate sensitivity and spend_delay impact. On CTV, demonstrates the reverse griefing direction (hot-key attacker triggers unvault, defender must sweep to cold). Keyless recovery griefing is a known tradeoff discussed in Ingala's MATT vault design (2023); this experiment quantifies the per-round cost asymmetry and projects it across fee environments.

**Threat model — forced-recovery griefing (CCV):**
- Attacker: Needs NO key material. Can observe the mempool and broadcast transactions. This is the minimum viable attacker — any entity with a Bitcoin node.
- Goal: Deny vault liveness by front-running legitimate unvault transactions with recovery broadcasts. Success = the vault owner cannot complete any withdrawal.
- Attack cost: One recovery transaction per round (~R vbytes × fee_rate). Front-running advantage: attacker monitors mempool for unvault txs, broadcasts recovery with higher fee before unvault confirms.
- Payoff: Zero direct financial gain. Pure denial of service.
- Rationality condition: Only rational with external incentive (competitor, extortionist, state actor). Cost is low — sustained griefing for 10 rounds at 10 sat/vB costs ~18,000 sats.
- The asymmetry between attacker and defender is threefold and empirically quantifiable: (a) trigger vsize > recovery vsize (ratio measured empirically), (b) defender bears opportunity cost of delayed withdrawal per round, (c) attacker has first-mover advantage via mempool monitoring.
- Defender response: Re-trigger with higher fees. Wait for low-fee periods. Use package relay (BIP 331) for atomic unvault+withdrawal. Out-of-band miner submission.
- Residual risk: No direct fund loss — the attack is liveness-only. Maximum damage = indefinite withdrawal delay + cumulative re-trigger fees. However, indefinite liveness denial may be operationally severe: a vault owner unable to access funds for an extended period faces real economic cost (missed payments, margin calls, opportunity cost). The severity depends on deployment context.

**CTV analog — hot-key forced-sweep griefing:**
- Attacker: Has the hot key. Can trigger unvault, forcing defender to sweep to cold.
- Goal: Force the defender's watchtower to repeatedly sweep to cold, consuming fees and denying withdrawal.
- Cost: One unvault trigger per round. Higher bar than CCV (requires compromised hot key).
- Escalation: If attacker also has the fee key, griefing escalates to fund theft via descendant-chain pinning (see fee_pinning experiment).

### G. ccv_edge_cases [ccv_only, security]
Tests three CCV-specific edge cases classified as developer footguns, not adversarial attacks.

**Threat model — mode confusion (CCV) [EMPIRICAL]:**
- Method: Constructs raw Tapscript leaves with OP_CHECKCONTRACTVERIFY using each flag value (0, 1, 2, 3, 4, 7, 128, 255), funds them into P2TR outputs on regtest, and attempts mutated spends redirecting funds to an attacker address.
- Defined modes (0-3): CCV enforces covenant rules — mutated spend is rejected.
- Undefined modes (4, 7, 128, 255): OP_SUCCESS triggers — script succeeds unconditionally, attacker steals funds.
- Uses pymatt's StandardAugmentedP2TR + StandardClause with custom CScript to construct each test contract, and ContractManager to fund/spend on regtest.
- Impact if deployed: An output with an undefined mode has zero covenant enforcement. Anyone can spend it. Severity: Critical if deployed, but this is a static-analysis-catchable bug, not a runtime attack.
- Design tradeoff: OP_SUCCESS enables clean soft-fork upgrades (new flag meanings without hard forks) but creates a silent failure mode for developers.

**Threat model — keypath bypass (Taproot misconfiguration):**
- Attacker: Has the private key corresponding to the Taproot internal key. This only exists if the developer passed a real public key as `alternate_pk` instead of using a NUMS point.
- Goal: Spend vault output via Taproot keypath, bypassing all CCV enforcement.
- Cost: One keypath spend (~57 vbytes witness). Trivial.
- Payoff: Full vault balance.
- Rationality: If the misconfiguration exists, always rational. But the misconfiguration itself is the vulnerability — the pymatt default (`alternate_pk=None`) makes this impossible. This is Taproot security hygiene, not a CCV-specific finding.

**Threat model — sentinel confusion (-1 vs 0):**
- Not an adversarial attack. Developer error during custom contract authoring. Impact: a clause that skips a check it should perform, or fails when it should succeed. Mitigated by typed APIs and named constants in pymatt.

### H. watchtower_exhaustion [security, quantitative, revault]
Tests the revault splitting attack described by halseth in the OP_VAULT discussion: an attacker with the trigger key repeatedly calls trigger_and_revault (CCV) or start_withdrawal with partial amounts (OP_VAULT), creating a cascade of Unvaulting UTXOs that the watchtower must individually recover. Applies to any vault design with revault capability (CCV, OP_VAULT). CTV is immune (no revault).

**Phases:**
1. Per-transaction cost measurement (trigger_and_revault and recovery vsize).
2. Chained splits (up to 50) with per-split vsize measurement — verifies vsize is structurally constant regardless of vault balance (balance-independence check), validating linear extrapolation.
3. Variable withdrawal fraction analysis: compares dust (546 sats), 10%, 25%, and 50% of remaining balance per split. Identifies attacker-optimal strategy and recovery viability at high fee rates. Each fraction strategy creates its own vault and runs empirical splits.
4. Economic analysis: fee rate scenario table ([1, 5, 10, 50, 100, 500] sat/vB), splits-to-exhaust, min safe vault, watchtower reserve per block.
5. halseth estimate verification (~3,000 chunks/block, ~0.3 BTC watchtower reserve).
6. Batched recovery analysis: estimates overhead amortization from batching multiple recoveries into one tx. Projects savings for batch sizes 1-100 and computes the fee-rate extension factor.
7. spend_delay sensitivity: analyzes how different CSV values (10, 20, 50, 144, 288 blocks) affect the attacker's capacity and the watchtower's ability to keep pace.

**Threat model — watchtower fee exhaustion (CCV):**
- Attacker: Has the unvault (trigger) key. Can observe mempool, broadcast transactions. No hashrate, no recovery key (recovery is keyless — anyone can call it).
- Goal: Force the watchtower to spend more on recovery fees than the remaining vault value, causing rational abandonment of some Unvaulting UTXOs. Attacker then completes withdrawal on unrecovered UTXOs after CSV timelock expires.
- Attack cost: One trigger_and_revault transaction per split (~T vbytes × fee_rate). Cumulative: N × T × fee_rate for N splits.
- Payoff: Value of any Unvaulting UTXOs the watchtower abandons. The attacker set the CTV template destination at trigger time, so unrecovered UTXOs pay out to the attacker.
- Rationality condition: Rational when cumulative attacker trigger cost < value of abandoned UTXOs. The critical threshold is when watchtower_recovery_cost_per_split > split_amount (dust limit). Above this threshold, every recovery costs the watchtower more than the split is worth — even if the watchtower recovers, it loses value.
- Defender response: Recover each Unvaulting UTXO individually, or batch recoveries (extending viable fee range). At high fee rates, watchtower may rationally abandon dust-sized UTXOs and focus on recovering larger ones. Long-term: increase spend_delay to give watchtower more time.
- Residual risk: At sufficiently high fee rates, the attacker can create a scenario where the watchtower's rational response is to abandon some UTXOs. This is the CCV equivalent of CTV's irrecoverable hot+fee key compromise — a state where fund loss is economically inevitable.
- CTV comparison: This attack is structurally impossible on CTV. CTV's lack of partial withdrawal means the attacker can only trigger one unvault of the full amount. This is the cost of CCV's revault flexibility.

**Threat model — watchtower fee exhaustion (OP_VAULT) [TM7]:**
- Attacker: Has the trigger key. Does NOT have recoveryauth key. Can observe mempool, broadcast transactions.
- Goal: Same as CCV — exhaust watchtower fees via repeated splitting.
- Attack cost: One start_withdrawal (partial) per split (~292 vB × fee_rate — higher than CCV's 162 vB due to 2-input/3-output structure). Cumulative: N × 292 × fee_rate.
- Structural difference from CCV: Recovery requires the recoveryauth key (246 vB per recovery, vs CCV's 122 vB keyless). The watchtower MUST hold this key. Per-recovery cost is 2× CCV's, shifting the economic threshold: dust UTXOs become unrecoverable at lower fee rates.
- Measured vsizes: trigger_and_revault=292 vB, recover=246 vB. Verified stable across 5 splits (range=0).
- Defender response: Same as CCV (batch recoveries, increase spend_delay), plus: if recoveryauth key is compromised, the attacker can ALSO grief the recovery (see TM6 in §4.1).
- Residual risk: Identical structure to CCV — at high fees, watchtower rationally abandons dust UTXOs. Higher per-recovery cost means the threshold is reached sooner than CCV.

### J. fee_sensitivity [analytical, quantitative, fee_management]
Synthesizes structural vsize measurements from ALL experiments (CTV, CCV, OP_VAULT) and computes economic costs, attack rationality thresholds, and crossover points across 6 historical Bitcoin fee environments (1, 10, 50, 100, 300, 500 sat/vB).

**Sections:**
1. Vault lifecycle cost comparison (CTV vs CCV vs OP_VAULT at each fee rate, as % of vault value).
2. Fee pinning attack economics: attack cost, dust capital, total deployment, rationality verdict.
3. Recovery griefing economics: per-round costs for CCV (keyless), OP_VAULT (keyed), and CTV (hot-key) variants.
4. Watchtower exhaustion economics: CCV and OP_VAULT splits-to-exhaust, batched recovery defense, viability crossover.
5. Cross-experiment synthesis: three-way attack severity matrix, deployment guidance.

This is an analytical experiment — it uses structural vsize constants (deterministic) and does not require on-chain transactions.

### K. opvault_recovery_auth [opvault_specific, security, quantitative]
Demonstrates authorized recovery as both a DEFENSE (anti-griefing property) and an ATTACK SURFACE (recoveryauth key compromise). Phase 1 measures normal authorized recovery cost. Phase 2 simulates N rounds of recoveryauth griefing (attacker front-runs triggers with recovery). Phase 3 compares with CCV's keyless griefing. Phase 4 demonstrates the anti-griefing property (unauthorized recovery is consensus-invalid).

**Threat model — recoveryauth key compromise:**
- Attacker: Has the recoveryauth key ONLY (not trigger key). Can observe mempool.
- Goal: Deny vault liveness by front-running triggers with OP_VAULT_RECOVER.
- Cost: One recovery tx per round. Higher bar than CCV (need key).
- Payoff: Zero direct gain — pure DoS. Funds go to owner's recovery address.
- Defender response: Rotate vault config with fresh recoveryauth key.
- Residual: Liveness denial only. Funds always safe at recovery address.

### L. opvault_trigger_key_theft [opvault_specific, security, quantitative]
Demonstrates trigger key compromise: attacker calls start_withdrawal() with attacker-controlled destination and races the watchtower's authorized recovery. Phase 1 shows the recovery race (watchtower wins). Phase 2 shows undefended theft (watchtower offline). Phase 3 analyzes economics. Phase 4 demonstrates the combined splitting + theft attack. Phase 5 provides cross-covenant comparison.

**Threat model — trigger key theft + recovery race [TM5]:**
- Attacker: Has the trigger key (xpub-derived — BIP-32 hierarchy expands derivation attack surface). Does NOT have recoveryauth key.
- Goal: Steal funds by triggering withdrawal to attacker-controlled address.
- Cost: One trigger tx (~292 vB, measured) + waiting spend_delay blocks. Trigger output is CTV-locked (shared structural property with CTV).
- Defense: Active watchtower broadcasts OP_VAULT_RECOVER (~246 vB) before CSV expires. Three-key separation (trigger, recoveryauth, recovery) means compromise of trigger alone is insufficient for theft IF watchtower is active.
- OP_VAULT-specific: xpub-derived trigger key (vs single Schnorr key in CTV/CCV), CTV-locked trigger output (shared with CTV, distinct from CCV's CCV-locked output), separate recoveryauth defense layer (unique to OP_VAULT).
- Combined attack: Trigger key + splitting (watchtower exhaustion, TM7) is worst single-key case.
- Cross-covenant: Analogous to CTV hot-key theft and CCV trigger key theft, but structurally distinct in key derivation and defense mechanism.

**Threat model — dual-key compromise: trigger + recoveryauth [TM6]:**
- Attacker: Has BOTH the trigger key AND the recoveryauth key. Does NOT have the recovery destination key.
- Goal: Persistent liveness denial — trigger withdrawal, then front-run the watchtower's recovery with the attacker's own recovery (since attacker has recoveryauth key).
- Cost: ~292 vB trigger + ~246 vB recovery per cycle. Cumulative: N × 538 × fee_rate.
- Why NOT theft: Recovery always sends to the PRE-COMMITTED recovery address (set at vault creation). Even with both keys, the attacker cannot redirect recovery output. Funds arrive at the owner's cold storage.
- Severity: HIGH (persistent DoS, not theft). Strictly less severe than CTV's hot+fee dual-key compromise (which enables actual fund theft via fee-pinning bypass).
- CCV comparison: N/A — CCV has only one key (trigger). Recovery is keyless, so there is no second key to compromise. CCV's dual-key equivalent is trigger key alone (which is already TM3).
- Defender response: Rotate vault to new config with fresh keys. While the attack persists, funds accumulate at the recovery address — safe but inaccessible via normal withdrawal.
- Residual risk: Funds are safe but locked in a trigger→recover cycle until the attacker stops or the owner rotates. The cost projection for sustained attack: at 50 sat/vB, each cycle costs the attacker 538 × 50 = 26,900 sats.

### 4.1 Unified Threat Model Comparison Matrix

This matrix synthesizes the per-experiment threat models into a three-way comparison across all attack classes. Each row (TM1–TM7) corresponds to a distinct adversary profile. The "Measured vsize" column uses empirically verified values from regtest runs (see §4.2 for verification methodology).

**Key:**
- *Attacker cost* = vsize × fee_rate (structural; fee_rate is exogenous).
- *Severity* = worst achievable outcome if attack succeeds optimally.
- *N/A* = attack is structurally impossible on that covenant.
- *Exp* = experiment(s) that empirically test this threat model.

```
TM  Attack class              CTV                         CCV                         OP_VAULT                    Exp
──  ────────────────────────  ──────────────────────────  ──────────────────────────  ──────────────────────────  ───
1   Fee pinning               CRITICAL — 25-descendant    N/A (no CPFP anchor)        N/A (no CPFP anchor;        C
    (anchor-chain DoS)        chain blocks CPFP on                                    fee wallet is separate
                              tocold; cost ~2,750 sats                                UTXO, not an anchor)
                              + ~16,400 dust capital.
                              Enables fund theft if
                              combined with hot key (TM3).

2   Recovery griefing         MODERATE — hot key needed.  SEVERE — keyless, anyone     LOW — recoveryauth key      F, K
    (forced-recovery DoS)     Attacker sweeps to cold     can front-run triggers       needed.  Higher bar than
                              (reverse direction).        with recovery tx.            CCV, lower cost than CTV.
                              Cost: ~164 vB/round.        Cost: ~122 vB/round.         Cost: ~246 vB/round.
                              Can escalate to theft       Pure liveness denial.        Pure liveness denial.
                              with fee key.               Funds always safe.           Funds always safe.

3   Trigger key theft         SEVERE — hot key +          SEVERE — trigger key →       MODERATE — trigger key →    L, F
    (fund theft attempt)      fee key = fund theft.       withdrawal to attacker       withdrawal to attacker
                              Hot key alone = liveness    addr.  Watchtower races      addr.  Watchtower races
                              denial only (tocold).       via keyless recovery         via AUTHORIZED recovery
                              Cost: ~164 vB trigger.      (~122 vB).  No escalation    (~246 vB).  Recoveryauth
                                                          beyond single theft          key provides defense.
                                                          attempt per round.           No fee-key escalation.
                              Measured: 164 vB            Measured: 154 vB trigger     Measured: 292 vB trigger

4   Watchtower exhaustion     N/A (no revault — single    SEVERE — splitting attack    SEVERE — same splitting     H
    (splitting attack)        unvault of full amount;     via trigger_and_revault      mechanics as CCV, but
                              watchtower recovers in      creates N Unvaulting          recovery needs the
                              one tx).                    UTXOs.  At high fees,        recoveryauth key.  Same
                                                          dust-sized UTXOs become      economic thresholds,
                                                          uneconomic to recover.       higher per-recovery cost.
                              N/A                         Measured: trigger=162 vB,    Measured: trigger=292 vB,
                                                          recover=122 vB               recover=246 vB

5   Trigger key theft         N/A (CTV has hot key, not   N/A (CCV trigger key is      MODERATE — xpub-derived     L
    (OP_VAULT-specific:       xpub-derived; no revault    a single Schnorr key, not    trigger key hierarchy
    xpub-derived key,         to amplify attack)          xpub-derived; CCV row is     expands derivation
    CTV-locked output)                                    in TM3)                      attack surface.  Trigger
                                                                                       output is CTV-locked
                                                                                       (shared with CTV).
                                                                                       Three-key separation
                                                                                       (trigger, recoveryauth,
                                                                                       recovery) is unique.
                                                          N/A                          Measured: 292 vB trigger

6   Dual-key compromise       HOT+FEE → fund theft       N/A (only one key — trigger  TRIGGER+RECOVERYAUTH →      L, K
    (trigger + recovery/      (fee key enables pinning    key.  Recovery is keyless,    persistent liveness
    auth key)                 defense bypass).            so no second key to           denial.  Attacker
                              HOT alone → liveness only.  compromise.)                 triggers, then front-runs
                                                                                       watchtower's recovery.
                              SEVERITY: CRITICAL                                       Funds safe (recovery
                              (theft possible)            N/A                          addr is pre-committed).
                                                                                       SEVERITY: HIGH (DoS,
                                                                                       not theft).
                                                                                       Combined cost: ~292 vB
                                                                                       trigger + ~246 vB recover
                                                                                       per cycle.

7   Address reuse             CRITICAL — second deposit   SAFE — each funding creates  SAFE — ChainMonitor         B
    (user/wallet error)       to same CTV address is      an independent contract      rescans for all vault
                              permanently stuck or        instance.  Multiple          UTXOs at the address.
                              overpays miners.            deposits to same addr are    Each can be triggered
                                                          individually spendable.      and recovered normally.
```

**Inverse hierarchies** (from Experiment F):
- Griefing resistance:   OP_VAULT > CTV > CCV  (OP_VAULT's recoveryauth key blocks unauthorized recovery)
- Fund safety under key loss: CCV > CTV > OP_VAULT  (CCV's keyless recovery has no key-loss failure mode)
- These are structural inverses — higher griefing resistance requires a key whose loss is catastrophic.

**Design Space positioning** (from Experiment J):

|            | Flexibility | Security           | Complexity |
|------------|:-----------:|:------------------:|:----------:|
| CTV        | Low         | High (conditional) | Low        |
| CCV        | High        | Moderate           | Low        |
| OP_VAULT   | High        | High               | High       |

CTV's "conditional" security depends on relay policy (TRUC/v3 would eliminate TM1). CCV's "moderate" reflects keyless griefing (TM2/TM4). OP_VAULT's "high complexity" reflects three-key management and recoveryauth key-loss risk.

### 4.2 OP_VAULT Vsize Verification

The fee_sensitivity experiment (§J) uses structural vsize constants for economic projection. OP_VAULT values were initially hand-estimated from script structure analysis, then verified against empirical regtest measurements from lifecycle_costs, recovery_griefing, and watchtower_exhaustion runs (results/2026-02-21_143950/).

```
Transaction type          Estimated    Measured    Delta    Source experiment
────────────────────────  ─────────    ────────    ─────    ────────────────
tovault (deposit)         154 vB       154 vB       0      lifecycle_costs
trigger (start_withdrawal)200 vB       292 vB     +92      lifecycle_costs (2-in/3-out)
withdraw (CTV-locked)     130 vB       121 vB      -9      lifecycle_costs
recover (OP_VAULT_RECOVER)170 vB       246 vB     +76      recovery_griefing (2-in/2-out)
trigger_and_revault       210 vB       292 vB     +82      watchtower_exhaustion (= trigger)
```

**Why the estimates were wrong:** The hand estimates assumed 1-input transactions (vault UTXO only). In practice, OP_VAULT's `start_withdrawal()` always consumes a fee-wallet UTXO as a second input, producing a 2-input/3-output structure. Recovery similarly uses 2 inputs (triggered output + fee). This inflates all non-deposit transactions by ~80-90 vB compared to naive single-input estimates.

**Stability verification:** The watchtower_exhaustion experiment verified vsize constancy across 5 consecutive splits: trigger range=0 vB, recover range=0 vB. Vsize is structurally independent of vault balance — linear extrapolation from single-round measurements is valid.

All fee_sensitivity constants have been updated to use the measured values. The corrected lifecycle total is 567 vB (was 484 vB), making OP_VAULT ~37% more expensive than CCV's 418 vB lifecycle.

## 5. Adapter Details

### 5.1 CTVAdapter

Wraps `simple-ctv-vault/main.py`. Key mapping:
- `create_vault` → `Wallet.fund()` + `VaultPlan` + broadcast `tovault_tx`
- `trigger_unvault` → broadcast CTV-only `unvault_tx` (no signature)
- `complete_withdrawal` → broadcast `tohot_tx` (after CSV) or `tocold_tx` (immediate CTV)
- `recover` → delegates to cold sweep (`tocold_tx`)

Does not support: revault, batched trigger, keyless recovery.

### 5.2 CCVAdapter

Wraps `pymatt/examples/vault/vault_contracts.py` via `ContractManager`. Key mapping:
- `create_vault` → `manager.fund_instance(Vault, amount)`
- `trigger_unvault` → `instance("trigger")` with CTV hash
- `complete_withdrawal` → build CTV template tx + `manager.spend_and_wait()`
- `recover` → `instance("recover")(out_i=0)` (no signature)
- `trigger_revault` → `instance("trigger_and_revault")` with split outputs
- `trigger_batched` → multi-instance spend in single tx

Supports: revault, batched trigger, keyless recovery.

### 5.3 OPVaultAdapter

Wraps [jamesob/opvault-demo](https://github.com/jamesob/opvault-demo) — the upstream BIP-345 reference implementation using the `verystable` library. Docker has been removed; the adapter points `BITCOIN_RPC_URL` at the local regtest node. Key mapping:
- `create_vault` → programmatic `VaultConfig` + `VaultSpec` creation, deposit via `SingleAddressWallet`
- `trigger_unvault` → `start_withdrawal()` (Schnorr-signed trigger + CTV-locked withdrawal pair)
- `complete_withdrawal` → broadcast `trigger_spec.withdrawal_tx` (CTV template, after CSV delay)
- `recover` → `get_recovery_tx()` (authorized recovery with recoveryauth key)
- revault → automatic when withdrawal amount < vault balance (handled by `start_withdrawal()`)

Supports: revault (automatic partial withdrawal), batched trigger (multiple vault UTXOs in one tx), authorized recovery (requires recoveryauth key).
Does not support: keyless recovery (default config uses authorized recovery to prevent fee-griefing).

Dependencies: `verystable==28.1.0-dev`, `bip32`, `clii`, `rich` (see `simple-op-vault/requirements.txt`).

Requires: jamesob/bitcoin `2023-02-opvault-inq` branch (`switch-node.sh opvault`).
Note: This branch uses the legacy autotools build system (not cmake). Build with:
`arch -x86_64 bash -c './autogen.sh && ./configure --without-miniupnpc && make -j$(nproc)'` (Rosetta on Apple Silicon).
Binaries are at `src/bitcoind` and `src/bitcoin-cli`.

## 6. Path Conventions

Adapters resolve external repos relative to the vault-comparison directory:
- CTV repo: `../../simple-ctv-vault` (relative to adapters/)
- CCV repo: `../../pymatt` (relative to adapters/)
- OP_VAULT repo: `../../simple-op-vault` (relative to adapters/)

This means the expected workspace layout is:
```
research experiments/
├── simple-ctv-vault/
├── pymatt/
├── simple-op-vault/
├── vault-comparison/
├── switch-node.sh
├── context.md
└── REFERENCES.md
```

## 7. Node Requirements

Each adapter requires a specific Bitcoin node variant:
- CTVAdapter: Bitcoin Inquisition (`switch-node.sh inquisition`)
- CCVAdapter: Merkleize Bitcoin with CCV (`switch-node.sh ccv`)
- OPVaultAdapter: jamesob/bitcoin opvault branch (`switch-node.sh opvault`) — autotools build (`src/bitcoind`)

The runner switches nodes automatically by default. Use `--no-switch` to skip this if the node is already running.

## 8. Limitations of This Comparison

This framework compares specific reference implementations — `simple-ctv-vault` for CTV and pymatt's vault example for CCV — on Bitcoin regtest. Several caveats apply:

**(a) Protocol evolution.** CTV's fee-pinning vulnerability (Experiment D) depends on the current mempool relay policy. The TRUC/v3 transaction proposal (Bitcoin Core PRs #28948, #29496) would restrict descendant chains to one transaction, eliminating the 24-descendant pinning vector demonstrated here. If TRUC is adopted, CTV's worst-case failure mode narrows to hot-key compromise alone. Similarly, address-reuse risk (Experiment B) is mitigable by wallet-layer enforcement of single-use addresses — standard Bitcoin hygiene that vault-aware wallets would be expected to implement.

**(b) Implementation vs. design.** The measurements reflect these specific implementations, not the theoretical optimum for each covenant design. A production CTV vault could incorporate different fee-management strategies (e.g., anchor outputs, pre-signed fee bumps at multiple rates). A production CCV vault could implement anti-griefing heuristics, reputation-based recovery filtering, or bonded recovery mechanisms not present in pymatt's reference code.

**(c) CCV's griefing surface.** Keyless recovery griefing (Experiment F) and watchtower exhaustion (Experiment I) are presented as liveness-only attacks. However, indefinite liveness denial can be operationally severe — a vault owner unable to access funds faces real economic cost (missed payments, opportunity cost, margin calls). Whether theft risk or liveness risk is more consequential depends on the deployment context: institutional custody with redundant infrastructure may tolerate liveness attacks better than individual users.

**(d) Regtest validity.** All vsize measurements are structurally valid (same script produces the same witness on mainnet), but fee-market dynamics (miner behavior, mempool congestion, RBF competition) are absent from regtest. The fee sensitivity analysis (Experiment J) projects costs analytically rather than observing them in adversarial fee markets.

## 9. Extending the Framework

To add a new experiment:
1. Create `experiments/exp_<name>.py`
2. Decorate the `run` function with `@register(name=..., tags=[...])`
3. Add a force-import line in `run.py` so the decorator fires at startup
4. The experiment receives a fully-set-up `VaultAdapter` with an active RPC connection

To add a new covenant adapter:
1. Subclass `VaultAdapter` in `adapters/<name>_adapter.py`
2. Implement all abstract methods and relevant optional methods
3. Add a case to `run.py:get_adapter()`
4. Document the node requirements and path conventions
