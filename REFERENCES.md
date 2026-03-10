# Related Work and References

## 1. References

### [MES16] Möser, Eyal, Sirer — "Bitcoin Covenants"
Malte Möser, Ittay Eyal, Emin Gün Sirer. "Bitcoin Covenants." In *Financial Cryptography and Data Security Workshops* (3rd Workshop on Bitcoin and Blockchain Research), FC 2016. Springer LNCS, pp. 126–141.
DOI: [10.1007/978-3-662-53357-4_9](https://doi.org/10.1007/978-3-662-53357-4_9)
PDF: https://maltemoeser.de/paper/covenants.pdf

The foundational work establishing covenants as a mechanism for vault-based custody on Bitcoin. Introduces recursive covenants and their application to restricting how coins may be spent across future transactions.

### [SHMB20] Swambo, Hommel, McElrath, Bishop — "Custody Protocols Using Bitcoin Vaults"
Jacob Swambo, Spencer Hommel, Bob McElrath, Bryan Bishop. "Custody Protocols Using Bitcoin Vaults." arXiv preprint, May 2020.
arXiv: [2005.11776](https://arxiv.org/abs/2005.11776)

The most comprehensive prior security analysis of vault protocols. Defines the deposit→unvault→withdraw lifecycle model, the watchtower monitoring assumption, and the threat model vocabulary (key compromise, fee management, recovery races) that subsequent work builds on. Our framework's adapter interface and threat model structure follow from this formalization.

### [Swa23] Swambo — "Evolving Bitcoin Custody"
Jacob Tyge Göker Swambo. "Evolving Bitcoin Custody." PhD thesis, King's College London, Department of Informatics, December 2022.
arXiv: [2310.11911](https://arxiv.org/abs/2310.11911)

Proposes the Ajolote autonomous custody system with formal security analysis of deleted-key covenants. The formal treatment of vault state transitions and adversarial models provides a theoretical foundation relevant to CTV's design constraints. Swambo [Swa23] analyzes deleted-key covenants formally; our framework extends the analysis to active-key covenant designs (CCV, OP_VAULT, CAT+CSFS) across four implementations with empirical measurements.

### [OS23] O'Beirne, Sanders — BIP-345 (OP_VAULT)
James O'Beirne, Greg Sanders. "BIP-345: OP_VAULT." Bitcoin Improvement Proposal, February 2023. Status: Withdrawn, superseded by BIP-443.
BIP text: https://bips.dev/345/
GitHub: https://github.com/bitcoin/bips/blob/master/bip-0345.mediawiki

The immediate predecessor to CCV-based vault designs, proposing dedicated OP_VAULT and OP_VAULT_RECOVER opcodes with amount-aware covenant checking. Its withdrawal in favor of BIP-443 reflects the development community's preference for general-purpose covenant primitives. The BIP-345 security analysis (recovery mechanisms, trigger authorization, watchtower requirements) directly informed CCV's design.

### [Har24] Harding — "OP_VAULT comments"
David A. Harding. "OP_VAULT comments." Delving Bitcoin, February 2024.
URL: https://delvingbitcoin.org/t/op-vault-comments/521

Contains the watchtower fee exhaustion analysis estimating ~3,000 revault chunks per block and ~0.3 BTC watchtower reserve requirements. Our experiment H (watchtower_exhaustion) empirically tests these estimates against measured CCV transaction sizes.

### [Ing23] Ingala — MATT/CCV design
Salvatore Ingala. "Merkleize All The Things" (MATT) proposal and subsequent CCV design discussions. bitcoin-dev mailing list, 2023–2024.
MATT proposal: https://gnusha.org/pi/bitcoindev/CAMhCMoH9uZPeAE_2tWH6rf0RndqV+ypjbNzazpFwFnLUpPsZ7g@mail.gmail.com/
Concrete opcodes: https://gnusha.org/pi/bitcoindev/CAMhCMoFYF+9NL1sqKfn=ma3C_mfQv7mj2fqbqO5WXVwd6vyhLw@mail.gmail.com/
BIP-443: https://bips.dev/443/
GitHub (BIP PR): https://github.com/bitcoin/bips/pull/1793
Implementation: https://github.com/bitcoin/bitcoin/pull/32080

Designer of CCV (BIP-443) and the pymatt framework. His mailing list discussions address keyless recovery griefing, mode confusion risks with undefined CCV flags, OP_SUCCESS semantics for undefined opcodes, and the cross-input DEDUCT accounting footgun.

### [Rub20] Rubin — BIP-119 (OP_CHECKTEMPLATEVERIFY)
Jeremy Rubin. "BIP-119: OP_CHECKTEMPLATEVERIFY." Bitcoin Improvement Proposal, January 2020.
BIP text: https://bips.dev/119/

Defines the CTV opcode. The BIP-119 discussion covers address reuse risks, fee management limitations, and the single-output commitment model.

### [Poe21] Poelstra — "CAT and Schnorr Tricks"
Andrew Poelstra. "CAT and Schnorr Tricks I" and "CAT and Schnorr Tricks II." Blockstream Research Blog, October–November 2021.
Part I: https://blog.blockstream.com/cat-and-schnorr-tricks-i/
Part II: https://blog.blockstream.com/cat-and-schnorr-tricks-ii/
Also: https://www.wpsoftware.net/andrew/blog/cat-and-schnorr-tricks-ii.html

Demonstrates that OP_CAT alone (without OP_CHECKSIGFROMSTACK) can achieve transaction introspection via a Schnorr discrete-log trick: forcing both the public key and nonce to equal the generator G collapses the signature equation into a deterministic hash of the message, effectively emulating CSFS. Part II constructs a two-phase vault (vault → staging) with recursive covenants, dynamic destination selection via a second output, and a cold-key reset model where compromise leads to a liveness battle rather than theft. Our CAT+CSFS vault uses a simplified variant: real CSFS instead of the G-trick, fixed destinations instead of dynamic, and unconstrained cold-key recovery instead of recursive staging resets. The cold key recovery experiment (Phase 5) models the cost tradeoff between these designs.

### [RP24] Ruffing, Poelstra — BIP-348 (OP_CHECKSIGFROMSTACK)
Tim Ruffing, Andrew Poelstra. "BIP-348: OP_CHECKSIGFROMSTACK." Bitcoin Improvement Proposal, 2024.
BIP text: https://bips.dev/348/

Formalizes OP_CHECKSIGFROMSTACK for Tapscript, enabling verification of Schnorr signatures against arbitrary messages on the stack. Combined with OP_CAT (BIP-347), enables the dual-verification pattern used in our CAT+CSFS vault: the same signature is checked by CSFS (against a stack-assembled sighash preimage) and CHECKSIG (against the real transaction sighash), proving that the witness-provided preimage data matches the actual transaction.

### [Rij24] Rijndael — "Basic vault prototype using OP_CAT"
Rijndael. "Basic vault prototype using OP_CAT." Delving Bitcoin, February 2024.
URL: https://delvingbitcoin.org/t/basic-vault-prototype-using-op-cat/576
GitHub: https://github.com/taproot-wizards/purrfect_vault
Covered in: Bitcoin Optech Newsletter #291, February 28, 2024.

A Rust proof-of-concept vault implementation using only OP_CAT (BIP-347) and existing consensus rules — no OP_CHECKSIGFROMSTACK required. Uses the Schnorr discrete-log trick (forcing pubkey and nonce to generator G) described by Poelstra [Poe21] to emulate CSFS, achieving transaction introspection with a single opcode. The vault enforces amount preservation (trigger output matches input), relative timelocks (contest period), and destination locking (withdrawal address fixed at trigger time). Our CAT+CSFS vault differs by using real CSFS (BIP-348) instead of the G-trick, which simplifies the witness structure and avoids the requirement that the signing key be the generator, at the cost of requiring a second soft fork (BIP-348 in addition to BIP-347).

### Additional references

**Bitcoin Optech Newsletter.** Multiple editions covering CPFP carve-out, package relay, v3/TRUC transactions, and OP_VAULT analysis. Cite specific editions for fee pinning context.
URL: https://bitcoinops.org/en/newsletters/

**[Ria23] Antoine Riard — "Replacement Cycling Attacks on Lightning Network."** Full Disclosure, bitcoin-dev mailing list, October 2023. Demonstrates that an attacker can use transaction replacement to cycle out a victim's time-sensitive HTLC-timeout transaction from the mempool, enabling fund theft.  While the specific mechanics target Lightning HTLCs (not CTV vault anchors), the underlying class of attack — manipulating mempool relay policy to prevent confirmation of time-critical transactions — is shared with the descendant-chain pinning demonstrated in experiment D.

**Gloria Zhao.** Package relay and v3/TRUC transaction proposals (Bitcoin Core PRs [#28948](https://github.com/bitcoin/bitcoin/pull/28948), [#29496](https://github.com/bitcoin/bitcoin/pull/29496)). TRUC adoption would eliminate the descendant-chain pinning vector demonstrated in experiment D.

**[WD24] Pieter Wuille, Suhas Daftuar — Cluster Mempool.** Bitcoin Core project, 2024-2025. Replaces per-transaction ancestor/descendant limits with cluster-based mempool evaluation.  Relevant to experiment D (fee pinning): the 25-descendant limit exploited by the pinning attack may change under cluster mempool's different eviction and relay logic.  See Bitcoin Optech topic page: https://bitcoinops.org/en/topics/cluster-mempool/. The cluster mempool redesign is ongoing as of 2026; its impact on CTV vault pinning is a forward-looking consideration.

### [OB25] O'Beirne — "Withdrawing OP_VAULT (BIP-345)"
James O'Beirne. "Withdrawing OP_VAULT (BIP-345)." Delving Bitcoin, 2025.
URL: https://delvingbitcoin.org/t/withdrawing-op-vault-bip-345/1670

Confirms OP_VAULT (BIP-345) was withdrawn in favor of CCV (BIP-443). Relevant context for why both designs are compared despite OP_VAULT being deprecated — the architectural comparison remains valuable for understanding design tradeoffs.

### [CTV-CSFS25] "CTV+CSFS: Can we reach consensus on a first step towards covenants?"
Delving Bitcoin discussion thread, 2025.
URL: https://delvingbitcoin.org/t/ctv-csfs-can-we-reach-consensus-on-a-first-step-towards-covenants/1509

Community discussion on bundling CTV (BIP-119) and CSFS (BIP-348) as a concrete soft-fork proposal. Relevant context for why the CTV and CAT+CSFS designs are compared alongside CCV.

### [Ing25a] Ingala — "OP_CHECKCONTRACTVERIFY and its amount semantic"
Salvatore Ingala. "OP_CHECKCONTRACTVERIFY and its amount semantic." Delving Bitcoin, 2025.
URL: https://delvingbitcoin.org/t/op-checkcontractverify-and-its-amount-semantic/1527

Discusses CCV amount handling modes, directly relevant to the DEDUCT accounting footgun demonstrated in experiment E (multi_input).

### [BSSL25] B-SSL — "Covenant-Free Vault Model"
"Concept Review: B-SSL (Bitcoin Secure Signing Layer) — Covenant-Free Vault Model Using Taproot, CSV, and CLTV." Delving Bitcoin, October 2025.
URL: https://delvingbitcoin.org/t/concept-review-b-ssl-bitcoin-secure-signing-layer-covenant-free-vault-model-using-taproot-csv-and-cltv/2047

A Taproot-based vault design without covenants, using only existing opcodes (CSV, CLTV) with multi-path spending conditions. Relevant as a baseline comparison point for what is achievable without new opcodes. Our framework focuses on covenant-based designs that provide stronger guarantees (e.g., destination locking, amount-aware withdrawal) not achievable with CSV/CLTV alone.

### [covenants.info] Community Covenant Comparison
covenants.info — community-maintained feature comparison matrix for Bitcoin covenant proposals.
URL: https://covenants.info/

Qualitative feature-matrix comparison. Our work differs by providing quantitative empirical measurements under controlled conditions rather than feature checklists.

---

## 2. Per-Experiment Relationship to Prior Work

### A. lifecycle_costs

Swambo et al. [SHMB20](https://arxiv.org/abs/2005.11776) define the deposit→unvault→withdraw lifecycle model. This experiment measures the vsize of each transaction step for both CTV ([BIP-119](https://bips.dev/119/)) and CCV ([BIP-443](https://bips.dev/443/)) implementations on regtest, providing the cost baseline that all security experiments draw on.

### B. address_reuse

Address reuse risk in CTV is discussed in the [BIP-119](https://bips.dev/119/) mailing list and O'Beirne's [OP_VAULT](https://bips.dev/345/) analysis [OS23]: CTV commits to specific input/output structure at vault creation, making subsequent deposits to the same address unspendable. CCV's resilience (each funding creates an independent contract instance) follows from Ingala's design [Ing23](https://bips.dev/443/). This experiment demonstrates the failure mode empirically on regtest — consensus rejection of the second deposit's spend attempt and the resulting stuck UTXO.

### C. fee_pinning

Descendant-chain pinning is extensively discussed in [Bitcoin Optech](https://bitcoinops.org/en/newsletters/) and the Bitcoin Core PR discussions around v3/TRUC transactions ([#28948](https://github.com/bitcoin/bitcoin/pull/28948), [#29496](https://github.com/bitcoin/bitcoin/pull/29496)). Its application to CTV vault anchor outputs is noted in [BIP-119](https://bips.dev/119/) discussion. This experiment constructs an actual 24-descendant chain from a CTV vault's tocold anchor output on regtest, demonstrates that the descendant limit blocks CPFP on all outputs of the pinned transaction (not only the anchor), and provides a parameterized cost model across fee environments. Zhao's TRUC proposal would eliminate this attack vector if adopted.

### D. revault_amplification

CCV's partial withdrawal capability (trigger_and_revault) is a core feature of [BIP-443](https://bips.dev/443/); CTV's all-or-nothing unvault is inherent to [BIP-119](https://bips.dev/119/). This experiment measures the cumulative vsize cost of N sequential partial withdrawals on CCV.

### E. multi_input

CTV's inability to batch triggers follows from [BIP-119](https://bips.dev/119/)'s commitment to input count and spend index. CCV batching and the cross-input DEDUCT accounting footgun are documented by Ingala ([BIP-443](https://bips.dev/443/)). This experiment measures the vsize scaling curve for CCV batched triggers (marginal weight per vault, projected ceiling at ~1,600 vaults per standard transaction) and demonstrates the cross-input DEDUCT accounting failure on regtest.

### F. recovery_griefing

Keyless recovery griefing is identified by Ingala ([Ing23](https://bips.dev/443/), bitcoin-dev mailing list) as an inherent property of CCV's permissionless recovery design. The vault custody threat model follows Swambo et al. [SHMB20](https://arxiv.org/abs/2005.11776). This experiment measures the vsize asymmetry between trigger (154 vB) and recovery (122 vB) transactions, simulates a 10-round griefing loop, and compares the CCV griefing surface (keyless, wider, liveness-only) with the CTV analog (hot-key sweep, narrower, escalates to fund theft via fee pinning).

### G. ccv_edge_cases

The OP_SUCCESS semantics for undefined CCV flags are a deliberate consensus design choice for forward compatibility, specified in [BIP-443](https://bips.dev/443/). Mode confusion risk is discussed by Ingala ([Ing23](https://gnusha.org/pi/bitcoindev/CAMhCMoFYF+9NL1sqKfn=ma3C_mfQv7mj2fqbqO5WXVwd6vyhLw@mail.gmail.com/)). Keypath bypass is inherent to Taproot (BIP-341), not CCV-specific. This experiment constructs P2TR outputs with undefined CCV flag bytes (4, 7, 128, 255), funds them on regtest, and confirms spends succeed unconditionally via OP_SUCCESS. See also experiment I (ccv_mode_bypass) for the production-vault escalation.

### H. watchtower_exhaustion

The revault splitting attack originates with halseth in the OP_VAULT discussion, with quantitative estimates by Harding [Har24](https://delvingbitcoin.org/t/op-vault-comments/521) (~3,000 chunks per block, ~0.3 BTC watchtower reserve). CTV's immunity to this attack (all-or-nothing unvault) is noted in [OS23](https://bips.dev/345/). This experiment empirically tests Harding's estimates against measured CCV transaction sizes, extends the analysis with variable withdrawal fractions (dust through 50% of balance), quantifies batched recovery savings (~45% at 100 inputs), and identifies the fee-dependent crossover at which the attack shifts from infeasible to viable.

### I. ccv_mode_bypass

Escalates the synthetic mode-confusion finding from experiment G to production-shaped vault taptrees. Constructs a `VulnerableVault` with the same taptree structure as pymatt's production `Vault` (trigger + recover leaves), but the recover leaf's CCV uses an undefined mode value. Demonstrates the CCVWildSpend transition model: vault UTXO → zero typed outputs → funds into attacker-controlled UTXOs. Systematic mode sweep across 5 undefined values (3, 4, 7, 128, 255) confirms all produce complete covenant bypass. Prior art: Ingala [Ing23] documented OP_SUCCESS as a design decision for soft-fork safety; our contribution is the production-vault escalation and systematic measurement. Status: Verified via regtest measurement (2026-02-22).

### J. fee_sensitivity

Individual attack costs at specific fee rates appear in various discussions of the above works. This experiment synthesizes structural vsize measurements from all experiments and projects them across six historical fee environments (1–500 sat/vB), comparing how each threat model's rationality condition shifts with fee rate. The fee-dependent inversion of security rankings (finding #4) is, to our knowledge, a novel empirical finding — prior analyses compared designs at single fee points, masking the crossover.

### K. opvault_recovery_auth

The authorized recovery mechanism is specified in [BIP-345](https://bips.dev/345/) §Recovery and analyzed by O'Beirne in the context of anti-griefing design. The recoveryauth key requirement was O'Beirne's explicit response to the keyless recovery griefing problem identified by Ingala [Ing23]. This experiment quantifies the authorized recovery cost (246 vB, measured), simulates recoveryauth-keyed griefing, and compares with CCV's keyless griefing surface. The key-loss risk observation (recoveryauth loss = permanent inability to recover) follows from the design but is not highlighted in [OS23] — we make it explicit as the cost of the anti-griefing property.

### L. opvault_trigger_key_theft

Trigger key compromise is the standard adversary model for vault security, analyzed in [SHMB20] and [OS23]. OP_VAULT-specific aspects: the xpub-derived trigger key hierarchy ([BIP-345](https://bips.dev/345/) §Key management), CTV-locked trigger output (shared with CTV), and three-key separation (trigger, recoveryauth, recovery). The dual-key compromise analysis (trigger + recoveryauth = persistent liveness denial, NOT theft) follows from the pre-committed recovery address design in BIP-345 — recovery always sends to the address fixed at vault creation. This is structurally less severe than CTV's hot+fee dual-key compromise (which enables actual fund theft via fee-pinning bypass).

### M. cat_csfs_hot_key_theft

Hot key compromise in the CAT+CSFS vault is structurally similar to CTV's: the hot key can trigger unvaults and complete withdrawals, but only to the pre-committed destination (embedded as sha_single_output in the script). The dual-verification pattern (CSFS + CHECKSIG) was proposed by Poelstra [Poe21] and formalized by Ruffing/Poelstra [RP24]. The sighash preimage splitting technique used in the experiment follows from BIP-342 (Tapscript) sighash structure. Rijndael's purrfect_vault [Rij24] demonstrates that OP_CAT alone (without CSFS) can achieve similar introspection via the Schnorr G-trick; our vault uses real CSFS for a simpler witness structure.

### N. cat_csfs_witness_manipulation

Tests witness-level attacks against the CAT+CSFS introspection mechanism: prefix/suffix tampering, sha_single_output substitution, and signature reuse across different transaction contexts. The dual-verification constraint (CSFS against stack-assembled preimage + CHECKSIG against real sighash) is the core defense. Prior art: Poelstra [Poe21] describes the general introspection-via-signature-verification technique; Rijndael [Rij24] demonstrates the approach in a working vault prototype using the Schnorr G-trick (without CSFS). This experiment stress-tests robustness of the CSFS variant.

### O. cat_csfs_destination_lock

The fixed-destination property of our CAT+CSFS vault (sha_single_output embedded at creation time) contrasts with Poelstra's [Poe21] dynamic destination design (destination encoded in a second output at trigger time) and with CCV/OP_VAULT (destination chosen at trigger time). Phase 4 includes a design comparison noting Poelstra's alternative and the security tradeoff: fixed destination = smaller hot-key attack surface; dynamic destination = operational flexibility at the cost of hot-key redirection risk.

### P. cat_csfs_cold_key_recovery

The unconstrained cold-key recovery (bare OP_CHECKSIG) is the simplest possible recovery mechanism but also the weakest. Phase 5 models the alternative design from Poelstra [Poe21]: recursive staging resets where cold key compromise leads to a liveness battle rather than immediate theft. Cost projections compare per-round battle expenses (owner trigger + attacker reset) across fee environments. The Poelstra reset model would upgrade CAT+CSFS recovery security from rank #4 (immediate theft) to rank #2 (liveness denial, matching OP_VAULT).

---

## 3. Contribution Summary

This work provides an empirical comparison framework for CTV ([BIP-119](https://bips.dev/119/)), CCV ([BIP-443](https://bips.dev/443/)), OP_VAULT ([BIP-345](https://bips.dev/345/)), and CAT+CSFS ([BIP-347](https://bips.dev/347/) + [BIP-348](https://bips.dev/348/)) vault designs. The threat models and attack vectors tested here originate from the works cited above — the conceptual contribution is measurement and cross-design synthesis, not vulnerability discovery. See `DESIGN.md` §1.1 for the full novelty statement.

**What prior work established (we quantify, not discover):**

- Vault lifecycle model, threat vocabulary, static-vs-dynamic vault distinction: Swambo et al. [SHMB20]
- Keyless recovery griefing as inherent CCV property: Ingala [Ing23]
- Fee pinning via descendant chains, TRUC/v3 mitigation: Zhao, Bitcoin Core PRs #28948/#29496
- Authorized recovery tradeoff, watchtower fee exhaustion estimates: O'Beirne/Sanders [OS23], Harding [Har24]
- CCV mode confusion with undefined OP_SUCCESS flags: Ingala [Ing23]
- CAT-based transaction introspection via dual signature verification: Poelstra [Poe21]
- Recursive staging reset as cold key compromise mitigation: Poelstra [Poe21]

**What the framework contributes:**

1. The first four-way empirical comparison — regtest-measured transaction sizes for CTV, CCV, OP_VAULT, and CAT+CSFS (16 experiments, structured threat models) under a uniform adapter interface. OP_VAULT measurements revealed the fee-input overhead (all non-deposit txs +80–90 vB vs estimates), correcting prior hand-estimates.

2. Fee-dependent inversion of security rankings — the cross-experiment fee sensitivity synthesis (experiment J) shows that the relative security ordering of vault designs flips depending on fee environment. In low-fee regimes, CCV/OP_VAULT are safer (splitting is infeasible); in high-fee regimes, watchtower exhaustion becomes feasible while CTV's fee pinning cost remains negligible. No prior analysis has demonstrated this crossover.

3. The inverse-ranking structural result — griefing resistance and fund safety under key loss are necessarily anti-correlated across designs (OP_VAULT > CTV > CCV for griefing resistance; CCV > CTV > OP_VAULT for key-loss safety). This is a necessary tradeoff, not an implementation artifact.

4. Empirical confirmation/correction of prior estimates — For OP_VAULT, we measure 3,427 splits/block (trigger_and_revault weight ~1,168 WU), consistent with Harding's [Har24] ~3,000 estimate. For CCV, the smaller trigger_and_revault transaction (162 vB vs OP_VAULT's 292 vB) yields approximately 6,172 splits/block — roughly 80% more than OP_VAULT, because Harding's analysis assumed OP_VAULT-sized transactions. OP_VAULT hand-estimated vsizes corrected (trigger: 200→292, recovery: 170→246). Parameterized economic models extending [Har24] with variable withdrawal fractions, batched recovery quantification, and spend-delay sensitivity.

5. OP_VAULT deprecation context — BIP-345 was withdrawn [OB25] in favor of CCV (BIP-443). Our comparison quantifies the economic justification: OP_VAULT's fee-input overhead costs 36% more per lifecycle than CCV, and 80-90 vB more per non-deposit transaction.
