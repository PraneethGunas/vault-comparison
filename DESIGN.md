# Vault Comparison Framework — Context

This document covers the architecture, design rationale, and experiment catalog for the vault comparison framework.

## 1. Purpose

This framework exists to produce reproducible, quantitative comparisons between Bitcoin vault covenant designs. It currently targets four implementations:

1. CTV vault (`simple-ctv-vault`) — OP_CHECKTEMPLATEVERIFY (BIP 119) single-hop vault
2. CCV vault (`pymatt`) — OP_CHECKCONTRACTVERIFY (BIP 443) + CTV full vault
3. OP_VAULT vault (`simple-op-vault` / opvault-demo) — OP_VAULT + OP_VAULT_RECOVER (BIP 345) + CTV
4. CAT+CSFS vault (`simple-cat-csfs-vault`) — OP_CAT (BIP 347) + OP_CHECKSIGFROMSTACK (BIP 348) dual-verification vault

The goal is to separate design-level tradeoffs from implementation-level bugs, and to measure concrete costs (vsize, fees, key requirements, attack surfaces) rather than relying on qualitative comparisons alone.

### 1.1 Prior Art and Contribution Scope

This work builds on a body of prior research in covenant-based vault custody. The full attribution mapping is in [`REFERENCES.md`](../REFERENCES.md).

**What is NOT new (prior art we build on):**

The vault lifecycle model and threat vocabulary follow Swambo et al. ([arXiv 2005.11776](https://arxiv.org/abs/2005.11776)), which formalized the deposit→unvault→withdraw structure, the watchtower monitoring assumption, and the fundamental tension between pre-committed transaction trees (CTV-style) and reactive covenant enforcement (OP_VAULT-style). Finding #4 (CTV immune to watchtower exhaustion but inflexible) restates their static-vs-dynamic vault distinction. The keyless recovery griefing vector (finding #2) was identified qualitatively by Ingala ([BIP-443](https://bips.dev/443/)) on the bitcoin-dev mailing list. The TRUC/v3 mitigation for descendant pinning (finding #1) is documented in Bitcoin Core PRs [#28948](https://github.com/bitcoin/bitcoin/pull/28948), [#29496](https://github.com/bitcoin/bitcoin/pull/29496). The authorized-recovery tradeoff in OP_VAULT was analyzed by O'Beirne and Sanders ([BIP-345](https://bips.dev/345/)). Harding's watchtower fee exhaustion analysis ([Delving Bitcoin](https://delvingbitcoin.org/t/op-vault-comments/521)) estimated ~3,000 chunks/block and ~0.3 BTC watchtower reserve. The CCV mode confusion risk with undefined flags was discussed by Ingala as a known OP_SUCCESS design decision. We did not discover these vulnerabilities — they were identified in design-review contexts during 2020–2024.

**What IS new (our contribution is measurement and synthesis, not discovery):**

The conceptual contribution is a *unified measurement framework* that reveals how design-level tradeoffs compose under realistic fee environments. Specifically:

1. **The first four-way empirical comparison.** Regtest-measured transaction sizes for CTV, CCV, OP_VAULT, and CAT+CSFS under a uniform adapter interface (16 experiments, 12 threat models). Prior analysis compared at most two designs, or used estimates rather than measured values. The OP_VAULT vsize measurements reveal the fee-input overhead: all non-deposit transactions are 80–90 vB larger than expected (§4.2), making OP_VAULT's lifecycle 36% more expensive than CCV's.

2. **Fee-dependent inversion of security rankings.** The cross-experiment fee sensitivity synthesis (experiment J) shows that the *relative* security ordering of vault designs flips depending on fee environment. In low-fee regimes (1–10 sat/vB), CCV and OP_VAULT are safer than CTV (fee pinning is cheap but splitting is infeasible). In high-fee regimes (100–500 sat/vB), watchtower exhaustion becomes feasible against CCV/OP_VAULT while CTV's fee pinning cost remains negligible — the security ordering inverts. This fee-dependent crossover is the strongest finding: no prior analysis has shown that the answer to "which vault is safest?" depends on the fee environment.

3. **The inverse-ranking structural result.** Griefing resistance and fund safety under key loss are anti-correlated across the original three designs: OP_VAULT > CTV > CCV for griefing resistance, CCV > CTV > OP_VAULT for key-loss safety. CAT+CSFS adds a new axis: it has the strongest hot-key theft resistance (griefing-only, no theft path) but the weakest cold-key recovery safety (unconstrained OP_CHECKSIG). This is a necessary tradeoff (not an implementation artifact): blocking unauthorized recovery *requires* a key whose loss disables recovery. Any vault design must choose a position on this axis.

4. **Empirical confirmation/correction of prior estimates.** Harding's ~3,000 chunks/block estimate is confirmed (measured: 3,427 CCV, structural). OP_VAULT hand-estimated vsizes were significantly wrong (trigger: 200→292, recovery: 170→246) due to the 2-input fee-wallet pattern.
5. **CCVWildSpend: full vault UTXO theft via OP_SUCCESS (TM8).** The CCV mode confusion risk was documented by Ingala as a design decision. Our contribution is (a) the `CCVWildSpend` transition model — a vault UTXO consumed with zero typed outputs, funds vanishing into attacker-controlled UTXOs; (b) systematic mode sweep confirming all undefined values (3, 4, 7, 128, 255) produce bypass; (c) escalation from synthetic contract to production-shaped Vault taptree. This is closer to a high-severity bug report than a research contribution, but the transition model and systematic sweep are new. **Verified via `exp_ccv_mode_bypass` on CCV regtest (2026-02-22).** All 5 undefined modes confirmed: THEFT CONFIRMED on each, 110 vB per bypass spend.

The per-experiment relationship to prior work is detailed in `REFERENCES.md` §2.

## 2. Protocol Background

This section summarizes the four covenant approaches and their vault constructions. Each subsection covers what the opcode commits to, what it does not, and how the vault lifecycle maps onto it.

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

### 2.4 OP_CAT + OP_CHECKSIGFROMSTACK (CAT+CSFS / BIP 347 + BIP 348)

CAT+CSFS is not a single covenant opcode but a pair of general-purpose opcodes that together enable transaction introspection via dual signature verification — a technique described in Andrew Poelstra's [CAT and Schnorr Tricks](https://blog.blockstream.com/cat-and-schnorr-tricks-i/) series.

`OP_CAT` (BIP 347) concatenates the top two stack elements. `OP_CHECKSIGFROMSTACK` (BIP 348) verifies a Schnorr signature against an arbitrary message on the stack (rather than the transaction sighash). By combining them, a script can:

1. Have the spender provide the BIP 342 sighash preimage fields as witness data
2. Use `OP_CAT` to assemble these into the full preimage on the stack
3. Use `OP_CHECKSIGFROMSTACK` to verify a signature against the assembled preimage
4. Use `OP_CHECKSIG` to verify the **same signature** against the real transaction sighash

If both checks pass with the same key and signature, the witness-provided preimage must match the real transaction. The script can embed a constant (e.g., `sha_single_output` — the SHA256 hash of the expected output) that the spender cannot override, effectively constraining the transaction's outputs.

**CAT+CSFS vault lifecycle** (`simple-cat-csfs-vault`):

```
Funded UTXO (P2WPKH)
    │
    │ tovault_tx (P2WPKH → P2TR)
    ▼
Vault UTXO (P2TR: trigger leaf + recover leaf)
    │                          \
    │ trigger_tx                recover_tx → cold wallet (P2WPKH)
    │ (hot key, CSFS+CHECKSIG)  (cold key, simple CHECKSIG)
    ▼
Vault-Loop UTXO (P2TR: withdraw leaf + recover leaf)
    │                          \
    │ withdraw_tx               recover_tx → cold wallet (P2WPKH)
    │ (hot key, CSV + CSFS+     (cold key, simple CHECKSIG)
    │  CHECKSIG)
    ▼
Destination (P2WPKH)
```

The vault uses two Taproot addresses, each with a 2-leaf taptree on a NUMS internal key (provably unspendable key-path). The trigger and withdraw leaves use the dual CSFS+CHECKSIG introspection pattern with `SIGHASH_SINGLE|ANYONECANPAY` (0x83), embedding `sha_single_output` constants that constrain outputs. The recover leaves are simple `cold_pk OP_CHECKSIG` with no covenant constraint.

**CAT+CSFS-specific properties:**

1. **Destination lock** — The withdrawal destination is fixed at vault creation time (`sha_single_output` is embedded in the script). Cannot be changed without recovery + re-vaulting. This is the most rigid output constraint of any vault design.
2. **Dual-verification security** — Hot key compromise cannot redirect funds. The attacker can only trigger to the pre-committed vault-loop output. Worst case is a grief attack (funds remain recoverable).
3. **Unconstrained recovery** — The recover leaf is `cold_pk OP_CHECKSIG` with no introspection. Cold key compromise = immediate, unrestricted fund theft. This is the weakest recovery path of the four vault designs.
4. **No recursive covenants** — The vault can only re-vault once (vault → vault-loop). No indefinite chaining because the script can't embed its own future scriptPubKey.
5. **Fee flexibility** — `SIGHASH_SINGLE|ANYONECANPAY` commits to one input and one output. Additional fee-paying inputs can be attached without breaking the covenant.
6. **520-byte stack limit** — The assembled preimage (227 bytes including TapSighash tag) is within the 520-byte OP_CAT consensus limit, with 293 bytes of headroom.

**CAT+CSFS-specific limitations:**

1. **Cold key is single point of failure** — No timelock, no watchtower window, no pre-committed recovery destination. Poelstra's [CAT and Schnorr Tricks II](https://blog.blockstream.com/cat-and-schnorr-tricks-ii/) proposes an alternative: recursive staging resets where the cold key returns funds to the same covenant (liveness battle, not theft). See the `cat_csfs_cold_key_recovery` experiment Phase 5 for the cost model.
2. **No partial withdrawal** — The entire vault amount flows through trigger → vault-loop → withdraw. No revault/splitting capability.
3. **Rigid destination** — Changing the withdrawal address requires a full recovery + re-deposit cycle. Poelstra's design avoids this by encoding the destination in a second output at trigger time, giving the hot key dynamic destination selection (but also a larger attack surface).
4. **No batched triggers** — Each vault UTXO has its own embedded sha_single_output; cannot batch across vaults.

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
├── collect_tx_metrics(record, rpc) → TxMetrics
├── get_internals() → dict           # Expose internal state for experiments
└── capabilities() → dict            # Programmatic capability discovery
```

Each adapter lazy-loads its vault implementation at `setup()` time via `UpstreamModuleLoader` (in `harness/module_loader.py`), which handles `sys.path` manipulation and module cache isolation. CTV and CAT+CSFS adapters share coin pool management via `CoinPool` (in `harness/coin_pool.py`).

Experiments dispatch on adapter capabilities (`supports_batched_trigger()`, `supports_revault()`) rather than adapter names, so adding a fifth adapter requires no experiment modifications — only implementing the abstract interface and declaring capabilities.

### 3.2 Data Types

- `VaultState` — opaque handle for a funded vault. Carries txid, amount, and adapter-specific `extra` dict. Experiments access internals via `adapter.get_internals()` rather than digging into `extra` directly.
- `UnvaultState` — handle for an unvaulting UTXO. Carries txid, amount, blocks remaining, and `extra`.
- `TxRecord` — broadcast transaction receipt. Carries txid, label, raw hex, and amount.
- `TxMetrics` — per-transaction measurements: vsize, weight, fee, input/output counts, script type, CSV blocks.
- `ExperimentResult` — collects all observations, tx metrics, and errors for one experiment run on one covenant.
- `ComparisonResult` — pairs results from two covenants for the same experiment.
- `ExperimentContext` — (in `experiments/experiment_base.py`) injected state bundle carrying adapter, result, rpc, and params. Provides shared helpers for lifecycle measurement (`create_and_measure_vault`, `trigger_and_measure`, `withdraw_and_measure`, `recover_and_measure`).

### 3.3 Experiment Registry

Experiments are discovered via the `@register` decorator in `experiments/registry.py`. Each experiment module defines a `run(adapter: VaultAdapter) -> ExperimentResult` function decorated with `@register(name=..., description=..., tags=[...])`.

Tags enable selective execution (e.g., `--tag core` runs all foundational experiments).

### 3.3.1 Experiment Categories (Tag Taxonomy)

Experiments are classified along two orthogonal axes: **scope** (which covenants the experiment meaningfully runs on) and **concern** (what the experiment measures).

**Scope tags:**
- `comparative` — True head-to-head comparison. Runs the same test on all four covenants, and the finding comes from the difference in outcomes. (lifecycle_costs, address_reuse, fee_pinning, recovery_griefing)
- `capability_gap` — Demonstrates a capability some covenants have that others lack. (multi_input, revault_amplification)
- `ccv_only` — Only runs on CCV. Tests CCV-specific semantics or developer footguns with no analog in other designs. (ccv_edge_cases, ccv_mode_bypass)
- `opvault_specific` — Only runs on OP_VAULT. Tests OP_VAULT-specific key management and authorized recovery. (opvault_recovery_auth, opvault_trigger_key_theft)
- `cat_csfs_only` — Only runs on CAT+CSFS. Tests dual-verification properties, witness manipulation, destination locking, and unconstrained recovery. (cat_csfs_hot_key_theft, cat_csfs_witness_manipulation, cat_csfs_destination_lock, cat_csfs_cold_key_recovery)

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
| cat_csfs_hot_key_theft | Fully valid (consensus-level signature verification) | N/A — dual-verification is consensus |
| cat_csfs_witness_manipulation | Fully valid (consensus-level sighash verification) | N/A — preimage checking is deterministic |
| cat_csfs_destination_lock | Fully valid (structural script property) | N/A |
| cat_csfs_cold_key_recovery | Fully valid (consensus-level spending) | Recovery race timing untested |

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
- Defined modes (0, 1, 2): CCV enforces covenant rules — mutated spend is rejected.
- Undefined modes (3, 4, 7, 128, 255): OP_SUCCESS triggers — script succeeds unconditionally, attacker steals funds.
- Pseudocode (checkcontractverify.md lines 75–76): `if flags < CCV_FLAG_CHECK_INPUT or flags > CCV_FLAG_DEDUCT_OUTPUT_AMOUNT: return success()`
- Valid range: [-1, 0, 1, 2]. Everything else → unconditional success.
- Uses pymatt's StandardAugmentedP2TR + StandardClause with custom CScript to construct each test contract, and ContractManager to fund/spend on regtest.
- Impact if deployed: An output with an undefined mode has zero covenant enforcement. Anyone can spend it. Severity: Critical if deployed, but this is a static-analysis-catchable bug, not a runtime attack.
- Design tradeoff: OP_SUCCESS enables clean soft-fork upgrades (new flag meanings without hard forks) but creates a silent failure mode for developers.

**Threat model — CCVWildSpend: full vault UTXO theft via OP_SUCCESS [TM8]:**
- Escalation of the mode confusion footgun to an actual Vault contract. Experiment: `exp_ccv_mode_bypass.py` (vault-comparison framework).
- Construction: A `VulnerableVault` identical to the production `Vault` taptree (trigger + recover leaves), except the recover leaf's CCV uses `mode=3` (or 4, 7, 128, 255).
- Attack: Anyone who can construct the witness path to the poisoned recover leaf can spend the vault UTXO to an arbitrary address. No signature, no output validation, no amount checking.
- Control: Same vault with `mode=0` rejects the identical spend (CCV checks output scriptPubKey against `recover_pk`).
- Sweep: All tested undefined modes (3, 4, 7, 128, 255) produce full covenant bypass.
- Severity: CRITICAL. This is the highest-severity CCV finding.
  - Single-byte encoding error causes complete fund loss.
  - The vault address and taptree are structurally indistinguishable from a correct vault.
  - Not a theoretical concern — realistic encoding paths include: off-by-one (mode=3, one past DEDUCT_OUTPUT_AMOUNT), unsigned cast (−2 → 254), byte truncation in serialization.
- Distinction from `mode_confusion_attack.py`: That test uses a synthetic `ModeConfusionContract`. This test uses the actual `Vault` taptree structure with only the mode value changed, demonstrating that the vulnerability affects production-shaped contracts.
- Prior art: Ingala documented OP_SUCCESS for undefined CCV flags as a design decision for soft-fork safety. The `CCVWildSpend` transition model (vault UTXO → zero typed outputs) and the systematic mode sweep are new empirical contributions.
- Status: **Verified on CCV regtest (2026-02-22).** Control (mode=0) correctly rejected mutated spend. All 5 undefined modes (3, 4, 7, 128, 255) accepted — THEFT CONFIRMED on each. Bypass spend vsize: 110 vB, weight: 438–440. Experiment: `vault-comparison/experiments/exp_ccv_mode_bypass.py`.

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
5. Cross-experiment synthesis: four-way attack severity matrix, deployment guidance.

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

### M. cat_csfs_hot_key_theft [cat_csfs_only, security, critical]
Tests whether a compromised hot key can redirect vault funds in the CAT+CSFS design. Phase 1 performs a normal trigger as control (measures trigger vsize: 221 vB). Phase 2 constructs a trigger transaction with the output redirected to an attacker address, signs with the hot key, and broadcasts — REJECTED by consensus ("Invalid Schnorr signature") because the attacker's output doesn't match the embedded `sha_single_output`. Phase 3 analyzes extra output injection via SIGHASH_SINGLE (additional outputs possible but covenant output is locked). Phase 4 provides a four-way severity comparison.

**Threat model — hot key theft (CAT+CSFS) [TM9]:**
- Attacker: Has the hot key. Cannot modify the script (sha_single_output is embedded at vault creation).
- Goal: Redirect vault funds to an attacker-controlled address.
- Result: IMPOSSIBLE. The dual CSFS+CHECKSIG verification binds the output to the pre-committed sha_single_output. Changing the output causes the stack-computed sighash to diverge from the real transaction sighash — one signature check fails.
- Residual capability: Grief attack only. The attacker can trigger unnecessary unvaults to the vault-loop, but funds remain recoverable by the cold key. The worst single-key outcome for CAT+CSFS is strictly weaker than CCV (where trigger key → withdrawal to attacker address) and OP_VAULT (same, modulo watchtower race).
- Measured: trigger vsize = 221 vB.
- Status: **Verified on Inquisition regtest (2026-03-01).** Mutated trigger rejected. Normal trigger accepted.

### N. cat_csfs_witness_manipulation [cat_csfs_only, security, critical]
Tests three independent witness-tampering attacks on the CAT+CSFS sighash preimage. Phase 1 is a control (normal trigger accepted). Phases 2–4 each tamper with a specific preimage field: nVersion in the prefix (byte 2: 0x02→0x03), codesep_pos in the suffix (0xFFFFFFFF→0x00000000), and hash_type (0x83→0x01). All three are rejected. Phase 5 performs stack size analysis: prefix=94B, sha_out=32B, suffix=37B, total preimage=163B, with TapSighash tag=227B, limit=520B, headroom=293B.

**Threat model — witness manipulation (CAT+CSFS) [TM10]:**
- Attacker: Has the hot key AND can provide arbitrary witness data.
- Goal: Construct a valid witness that passes both CSFS and CHECKSIG checks but spends to a different output than intended.
- Result: IMPOSSIBLE. Any byte-level change to the prefix or suffix causes the CSFS-checked sighash to diverge from the CHECKSIG-checked sighash. The embedded sha_single_output is the only invariant — all other fields must match exactly.
- Stack size analysis: The full preimage (163 bytes) + TapSighash tag prefix (64 bytes) = 227 bytes on the stack before SHA256. This is well within the 520-byte OP_CAT consensus limit with 293 bytes of headroom.
- Status: **Verified on Inquisition regtest (2026-03-01).** All three tampering vectors rejected.

### O. cat_csfs_destination_lock [cat_csfs_only, security, configuration]
Tests the unique destination-lock property of CAT+CSFS vaults. Phase 1 verifies that sha_single_output is embedded in the script and that normal withdrawal succeeds (210 vB). Phase 2 attempts withdrawal to an alternative address — REJECTED. Phase 3 measures the recovery escape hatch (125 vB) and calculates the destination rotation cost (~247 vB = recovery + new tovault). Phase 4 provides a four-way flexibility ranking.

**Design analysis — destination lock:**
- The CAT+CSFS vault has the most rigid destination constraint of any vault design. The sha_single_output hash (SHA256 of the destination amount + scriptPubKey) is embedded in the tapscript at vault creation time.
- To change the destination: recover to cold wallet (125 vB) + create new vault with new destination (~122 vB) = ~247 vB rotation cost.
- Flexibility ranking: CCV/OP_VAULT (destination specified at trigger time) > CTV (destination baked into CTV hash, but with more structural flexibility) > CAT+CSFS (destination baked into sha_single_output with no alternative path).
- Tradeoff: Rigidity eliminates trigger-key redirection attacks but requires recovery for any destination change.
- Status: **Verified on Inquisition regtest (2026-03-01).** Alternative destination rejected. Recovery escape hatch works.

### P. cat_csfs_cold_key_recovery [cat_csfs_only, security, critical]
Tests the unconstrained recovery path and cold key compromise. Phase 1 measures normal recovery from vault (125 vB) and vault-loop (125 vB). Phase 2 constructs a recovery transaction sending to an attacker address, signs with the cold key — ACCEPTED. Confirms cold key compromise = immediate, unrestricted theft. Phase 3 verifies no timelock on recovery (no OP_CHECKSEQUENCEVERIFY). Phase 4 provides a four-way recovery security ranking.

**Threat model — cold key compromise (CAT+CSFS) [TM11]:**
- Attacker: Has the cold (recovery) key. No other keys required.
- Goal: Steal all vault funds immediately.
- Result: SUCCESSFUL. The recover leaf is `cold_pk OP_CHECKSIG` — no covenant constraint, no output restriction, no timelock. The attacker sweeps funds to any address in a single transaction.
- Severity: CRITICAL. This is the most severe single-key compromise across all four vault designs.
- Comparison: CCV recovery is keyless but output-constrained (recover_pk). OP_VAULT recovery is key-authorized AND output-constrained (pre-committed recovery address). CTV recovery is CTV-constrained (pre-committed tocold transaction). CAT+CSFS recovery has no constraint at all.
- Recovery security ranking: CCV (output-constrained, keyless) > OP_VAULT (output-constrained, keyed) > CTV (CTV-constrained) > CAT+CSFS (unconstrained).
- Measured: recover vsize = 125 vB (from vault), 125 vB (from vault-loop).
- Status: **Verified on Inquisition regtest (2026-03-01).** Attacker recovery to arbitrary address accepted.

### 4.1 Unified Threat Model Comparison Matrix

This matrix synthesizes the per-experiment threat models into a four-way comparison across all attack classes. Each row (TM1–TM8) corresponds to a distinct adversary profile. The "Measured vsize" column uses empirically verified values from regtest runs (see §4.2 for verification methodology). TM8 (CCV mode bypass) is empirically verified via `exp_ccv_mode_bypass` (2026-02-22).

**Key:**
- *Attacker cost* = vsize × fee_rate (structural; fee_rate is exogenous).
- *Severity* = worst achievable outcome if attack succeeds optimally.
- *N/A* = attack is structurally impossible on that covenant.
- *Exp* = experiment(s) that empirically test this threat model.

```
TM  Attack class              CTV                         CCV                         OP_VAULT                    CAT+CSFS                    Exp
──  ────────────────────────  ──────────────────────────  ──────────────────────────  ──────────────────────────  ──────────────────────────  ───
1   Fee pinning               CRITICAL — 25-descendant    N/A (no CPFP anchor)        N/A (no CPFP anchor;        N/A (no CPFP anchor;        C
    (anchor-chain DoS)        chain blocks CPFP on                                    fee wallet is separate      SIGHASH_SINGLE|ACP allows
                              tocold; cost ~2,750 sats                                UTXO, not an anchor)        external fee inputs)
                              + ~16,400 dust capital.
                              Enables fund theft if
                              combined with hot key (TM3).

2   Recovery griefing         MODERATE — hot key needed.  SEVERE — keyless, anyone     LOW — recoveryauth key      LOW — cold key needed.      F, K
    (forced-recovery DoS)     Attacker sweeps to cold     can front-run triggers       needed.  Higher bar than    Highest bar: cold key is
                              (reverse direction).        with recovery tx.            CCV, lower cost than CTV.   typically offline/hardware.
                              Cost: ~164 vB/round.        Cost: ~122 vB/round.         Cost: ~246 vB/round.        Cost: ~125 vB/round.
                              Can escalate to theft       Pure liveness denial.        Pure liveness denial.       But: cold key = total theft
                              with fee key.               Funds always safe.           Funds always safe.          (TM11), so griefing is
                                                                                                                   irrelevant if key is
                                                                                                                   compromised.

3   Trigger key theft         SEVERE — hot key +          SEVERE — trigger key →       MODERATE — trigger key →    LOW — hot key can only      L, F, M
    (fund theft attempt)      fee key = fund theft.       withdrawal to attacker       withdrawal to attacker      trigger to pre-committed
                              Hot key alone = liveness    addr.  Watchtower races      addr.  Watchtower races     vault-loop output.
                              denial only (tocold).       via keyless recovery         via AUTHORIZED recovery     Cannot redirect funds.
                              Cost: ~164 vB trigger.      (~122 vB).  No escalation    (~246 vB).  Recoveryauth    Grief only.
                                                          beyond single theft          key provides defense.      Measured: 221 vB trigger.
                              Measured: 164 vB            Measured: 154 vB trigger     Measured: 292 vB trigger    Verified (exp_cat_csfs_
                                                                                                                   hot_key_theft)

4   Watchtower exhaustion     N/A (no revault — single    SEVERE — splitting attack    SEVERE — same splitting     N/A (no revault — single    H
    (splitting attack)        unvault of full amount;     via trigger_and_revault      mechanics as CCV, but       unvault of full amount,
                              watchtower recovers in      creates N Unvaulting          recovery needs the         same as CTV).
                              one tx).                    UTXOs.  At high fees,        recoveryauth key.  Same
                                                          dust-sized UTXOs become      economic thresholds,
                                                          uneconomic to recover.       higher per-recovery cost.
                              N/A                         Measured: trigger=162 vB,    Measured: trigger=292 vB,   N/A
                                                          recover=122 vB               recover=246 vB

5   Trigger key theft         N/A (CTV has hot key, not   N/A (CCV trigger key is      MODERATE — xpub-derived     N/A (CAT+CSFS has single   L
    (OP_VAULT-specific:       xpub-derived; no revault    a single Schnorr key, not    trigger key hierarchy       Schnorr hot key, not
    xpub-derived key,         to amplify attack)          xpub-derived; CCV row is     expands derivation          xpub-derived)
    CTV-locked output)                                    in TM3)                      attack surface.  Trigger
                                                                                       output is CTV-locked
                                                                                       (shared with CTV).
                                                                                       Three-key separation
                                                                                       (trigger, recoveryauth,
                                                                                       recovery) is unique.
                                                          N/A                          Measured: 292 vB trigger   N/A

6   Dual-key compromise       HOT+FEE → fund theft       N/A (only one key — trigger  TRIGGER+RECOVERYAUTH →      HOT+COLD → total theft     L, K, P
    (trigger + recovery/      (fee key enables pinning    key.  Recovery is keyless,    persistent liveness         (cold key alone is
    auth key)                 defense bypass).            so no second key to           denial.  Attacker           sufficient — see TM11).
                              HOT alone → liveness only.  compromise.)                 triggers, then front-runs   Dual compromise is
                                                                                       watchtower's recovery.     redundant.
                              SEVERITY: CRITICAL                                       Funds safe (recovery       SEVERITY: CRITICAL
                              (theft possible)            N/A                          addr is pre-committed).    (theft via cold key alone)
                                                                                       SEVERITY: HIGH (DoS,
                                                                                       not theft).
                                                                                       Combined cost: ~292 vB
                                                                                       trigger + ~246 vB recover
                                                                                       per cycle.

7   Address reuse             CRITICAL — second deposit   SAFE — each funding creates  SAFE — ChainMonitor         SAFE — each deposit         B
    (user/wallet error)       to same CTV address is      an independent contract      rescans for all vault       creates a new VaultPlan
                              permanently stuck or        instance.  Multiple          UTXOs at the address.       from the source coin.
                              overpays miners.            deposits to same addr are    Each can be triggered       P2TR address is unique
                                                          individually spendable.      and recovered normally.     per coin/amount.

8   CCV mode bypass           N/A (CTV has no CCV         CRITICAL — undefined CCV     N/A (OP_VAULT uses         N/A (CAT+CSFS uses         G
    (OP_SUCCESS via            opcode; script structure    mode values (3, 4, 7, 128,   OP_VAULT / OP_VAULT_RECOVER OP_CAT / OP_CSFS;
    undefined CCV flags)       is CTV-only)               255) cause OP_SUCCESS.        opcodes, not CCV)          no mode parameter)
                                                          Full covenant bypass: no
                                                          signature, no output
                                                          validation, no amount
                                                          checking.  A single-byte
                                                          encoding bug in wallet/
                                                          compiler → complete fund
                                                          loss.  CCVWildSpend:
                                                          vault UTXO → arbitrary
                                                          attacker-controlled
                                                          outputs.
                              N/A                         Measured: 0 vB marginal      N/A                        N/A
                                                          (no covenant check occurs)
                                                          Verified (exp_ccv_mode_bypass)

9   Hot key output            N/A (CTV hot key can        N/A (CCV trigger key can     N/A (OP_VAULT trigger key   IMPOSSIBLE — dual CSFS+    M
    redirection               complete withdrawal to      redirect to arbitrary        can redirect to arbitrary   CHECKSIG verification
    (CAT+CSFS-specific)       CTV-locked dest)            addr)                        addr, modulo watchtower)    binds output to embedded
                                                                                                                   sha_single_output.
                                                                                                                   Hot key can only grief
                                                                                                                   (trigger to vault-loop).
                              N/A                         N/A                          N/A                        Measured: 221 vB trigger
                                                                                                                   Verified (exp_cat_csfs_
                                                                                                                   hot_key_theft)

10  Witness tampering         N/A (no witness-provided    N/A (CCV checks are          N/A (OP_VAULT checks are    IMPOSSIBLE — any byte      N
    (CAT+CSFS-specific)       preimage fields)            opcode-level)                opcode-level)               change to prefix/suffix
                                                                                                                   causes sighash divergence.
                                                                                                                   3/3 tampering vectors
                                                                                                                   rejected (nVersion,
                                                                                                                   codesep_pos, hash_type).
                              N/A                         N/A                          N/A                        Verified (exp_cat_csfs_
                                                                                                                   witness_manipulation)

11  Cold key compromise       N/A (CTV cold sweep is      N/A (CCV recovery is         N/A (OP_VAULT recovery      CRITICAL — recover leaf    P
    (CAT+CSFS-specific:       CTV-constrained to          output-constrained to        is output-constrained       is cold_pk OP_CHECKSIG.
    unconstrained recovery)   pre-committed tocold)       recover_pk)                  to pre-committed addr)      No covenant, no timelock,
                                                                                                                   no output restriction.
                                                                                                                   Cold key = immediate
                                                                                                                   total theft.
                              N/A                         N/A                          N/A                        Measured: 125 vB recover
                                                                                                                   Verified (exp_cat_csfs_
                                                                                                                   cold_key_recovery)
```

**Inverse hierarchies** (from Experiments F, K, P):
- Griefing resistance:   CAT+CSFS ≈ OP_VAULT > CTV > CCV  (CAT+CSFS requires cold key; OP_VAULT requires recoveryauth key)
- Fund safety under key loss: CCV > CTV > OP_VAULT > CAT+CSFS  (CAT+CSFS cold key compromise = immediate unrestricted theft)
- Hot key theft resistance: CAT+CSFS > CTV > CCV ≈ OP_VAULT  (CAT+CSFS hot key cannot redirect; CTV needs fee key too; CCV/OP_VAULT can redirect modulo watchtower)
- These are structural inverses — stronger output binding (CAT+CSFS) trades flexibility for hot-key safety but exposes cold-key risk.

**Design Space positioning** (from Experiments J, M–P):

|            | Flexibility | Hot-key safety     | Cold-key safety    | Complexity |
|------------|:-----------:|:------------------:|:------------------:|:----------:|
| CTV        | Low         | High (conditional) | High               | Low        |
| CCV        | High        | Moderate           | High (keyless)     | Low        |
| OP_VAULT   | High        | High               | High (constrained) | High       |
| CAT+CSFS   | Low         | Highest            | Low (unconstrained)| Moderate   |

CTV's "conditional" hot-key safety depends on relay policy (TRUC/v3 would eliminate TM1). CCV's "moderate" reflects keyless griefing (TM2/TM4) and the OP_SUCCESS risk from undefined modes (TM8). OP_VAULT's "high complexity" reflects three-key management and recoveryauth key-loss risk. CAT+CSFS's "highest" hot-key safety reflects the dual-verification binding (TM9), but its "low" cold-key safety reflects unconstrained recovery (TM11).

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

### 4.3 Four-Way Lifecycle Vsize Verification

CTV, CCV, and OP_VAULT lifecycle vsizes verified against regtest measurements (results/2026-02-24_141827/). CAT+CSFS trigger, withdraw, and recover vsizes measured in security experiments (results/2026-03-01_143838/); tovault estimated from script structure (P2WPKH → P2TR, not yet measured via lifecycle_costs):

```
Covenant   tovault    trigger/unvault   withdraw   recover   total*   Script types
────────   ───────    ───────────────   ────────   ───────   ──────   ──────────────────────────
CTV        122 vB     94 vB             152 vB     —†        368 vB   bare_ctv → bare_ctv → p2wsh (2-out)
CCV        165 vB     154 vB            111 vB     —†        430 vB   p2tr (2-out) → p2tr → p2tr
OP_VAULT   154 vB     292 vB            121 vB     246 vB    567 vB   p2tr (2-out) → p2tr (2-in/3-out) → p2tr_ctv
CAT+CSFS   ~153 vB‡   221 vB            210 vB     125 vB    ~584 vB  p2tr → p2tr_cat_csfs → p2tr_cat_csfs
```

\* Total = tovault + trigger + withdraw (happy-path lifecycle). Recovery is a separate path.
† CTV and CCV recovery uses the cold/keyless path but was not measured separately in lifecycle_costs.
‡ CAT+CSFS tovault is estimated (~153 vB for P2WPKH → P2TR). Will be verified when lifecycle_costs runs on cat_csfs.

**CTV/CCV corrections (2026-02-24):** The initial fee_sensitivity constants used hand-estimated values (CTV total=426, CCV total=418). The lifecycle_costs measurement showed CTV is actually 58 vB cheaper (368 vs 426) because its bare CTV outputs are more compact than the assumed P2WSH wrapping, and its unvault witness is minimal (94 vs 164). CCV's deposit is 11 vB larger than estimated (165 vs 154) due to the 2-output structure. All fee_sensitivity constants updated to match measured values.

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

### 5.4 CATCSFSAdapter

Wraps `simple-cat-csfs-vault/vault.py` via `VaultPlan` and `VaultExecutor`. Key mapping:
- `create_vault` → `VaultPlan` construction + `executor.create_vault()` (P2WPKH → P2TR)
- `trigger_unvault` → `executor.trigger_unvault()` (dual CSFS+CHECKSIG signing, SIGHASH_SINGLE|ACP)
- `complete_withdrawal` → `executor.complete_withdrawal()` (CSV + dual CSFS+CHECKSIG)
- `recover` → `executor.recover(from_vault=True/False)` (simple cold key CHECKSIG)

Does not support: revault, batched trigger, keyless recovery.

Uses the same Bitcoin Inquisition node as CTVAdapter (`switch-node.sh inquisition`).

Dependencies: `python-bitcoinlib`, `buidl`, `clii` (see `simple-cat-csfs-vault/requirements.txt`).

## 6. Path Conventions

Adapters resolve external repos relative to the vault-comparison directory:
- CTV repo: `../../simple-ctv-vault` (relative to adapters/)
- CCV repo: `../../pymatt` (relative to adapters/)
- OP_VAULT repo: `../../simple-op-vault` (relative to adapters/)
- CAT+CSFS repo: `../../simple-cat-csfs-vault` (relative to adapters/)

This means the expected workspace layout is:
```
research experiments/
├── simple-ctv-vault/
├── pymatt/
├── simple-op-vault/
├── simple-cat-csfs-vault/
├── vault-comparison/
│   ├── config.py              # FrameworkConfig, FeeConstants, load_config()
│   ├── config.toml            # Tunable parameters
│   ├── harness/
│   │   ├── rpc.py             # RegTestRPC client
│   │   ├── metrics.py         # ExperimentResult, ComparisonResult, TxMetrics
│   │   ├── report.py          # JSON + markdown report generation
│   │   ├── coin_pool.py       # Shared CoinPool for CTV / CAT+CSFS
│   │   ├── module_loader.py   # UpstreamModuleLoader (sys.path isolation)
│   │   └── logging.py         # Structured logging (structlog / stdlib)
│   ├── adapters/
│   ├── experiments/
│   │   ├── experiment_base.py # ExperimentContext, shared lifecycle helpers
│   │   └── registry.py        # @register decorator, experiment discovery
│   └── tests/                 # pytest unit + integration tests
├── switch-node.sh
├── DESIGN.md
└── REFERENCES.md
```

## 7. Node Requirements

Each adapter requires a specific Bitcoin node variant:
- CTVAdapter: Bitcoin Inquisition (`switch-node.sh inquisition`)
- CCVAdapter: Merkleize Bitcoin with CCV (`switch-node.sh ccv`)
- OPVaultAdapter: jamesob/bitcoin opvault branch (`switch-node.sh opvault`) — autotools build (`src/bitcoind`)
- CATCSFSAdapter: Bitcoin Inquisition (`switch-node.sh inquisition`) — same node as CTV

The runner switches nodes automatically by default. Use `--no-switch` to skip this if the node is already running.

## 8. Limitations of This Comparison

This framework compares specific reference implementations — `simple-ctv-vault` for CTV, pymatt's vault example for CCV, `simple-op-vault` for OP_VAULT, and `simple-cat-csfs-vault` for CAT+CSFS — on Bitcoin regtest. Several caveats apply:

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
5. Use `ExperimentContext` and shared helpers from `experiment_base.py` to reduce boilerplate
6. Dispatch on adapter capabilities (`supports_batched_trigger()`, etc.), not adapter names

To add a new covenant adapter:
1. Subclass `VaultAdapter` in `adapters/<name>_adapter.py`
2. Implement all abstract methods and relevant optional methods
3. Implement `get_internals()` to expose adapter-specific state for experiments
4. Implement `capabilities()` to declare supported features
5. Use `UpstreamModuleLoader` from `harness/module_loader.py` for upstream repo imports
6. Use `CoinPool` from `harness/coin_pool.py` if the upstream uses a CTV-style coin pool
7. Add a case to `run.py:get_adapter()`
8. Add fee constants to `config.toml` under `[fees.<name>]`
9. Document the node requirements and path conventions
10. Add an integration test class in `tests/test_integration.py`

### 9.1 Testing

The test suite lives in `vault-comparison/tests/`:

- **Unit tests** (`test_lifecycle.py`, `test_harness.py`, `test_registry.py`, `test_config.py`, `test_logging.py`) — run without a Bitcoin node, using `MockAdapter` and `MockRPC` from `conftest.py`. These cover framework correctness: adapter lifecycle, metrics serialization, experiment registry, configuration loading, and structured logging.
- **Integration tests** (`test_integration.py`) — require a running Bitcoin node. Tagged `@pytest.mark.integration` and skipped by default. Each adapter has a lifecycle test class exercising create→trigger→withdraw and create→trigger→recover paths, plus capability assertions.

Run tests with:
```bash
cd vault-comparison
python -m pytest tests/ -m "not integration" -v    # unit tests only
python -m pytest tests/ -m integration              # integration tests (need node)
```
