# Empirical Comparison of Bitcoin Covenant Vault Designs

Comparative analysis framework for CTV (BIP-119), CCV (BIP-443), and OP_VAULT (BIP-345) vault implementations on Bitcoin regtest.

## Overview

This framework runs side-by-side experiments against three covenant vault implementations, measuring transaction costs, security properties, and capability differences. Each experiment produces on-chain measurements from regtest, not simulated or estimated values.

The three covenant proposals represent fundamentally different design philosophies for Bitcoin vaults: CTV commits to exact transaction templates at vault creation; CCV enforces contract rules dynamically at spend time; OP_VAULT provides purpose-built vault opcodes with authorized recovery and dynamic withdrawal targets.

## Repository Layout

```
research experiments/
├── README.md                 # This file
├── REFERENCES.md             # Prior art and per-experiment citations
├── DESIGN.md                 # Architecture, threat models, experiment catalog
├── switch-node.sh            # Node manager (Inquisition / CCV / OP_VAULT)
├── vault-comparison/         # Framework source
│   ├── run.py                # CLI runner
│   ├── run_full.sh           # Full pipeline (run all → analyze)
│   ├── analyze_results.py    # Consolidated report generator
│   ├── harness/              # Shared infra (RPC, metrics, reporting)
│   ├── adapters/             # Vault drivers (CTV, CCV, OP_VAULT)
│   ├── experiments/          # Experiment modules (12 experiments)
│   └── results/              # Timestamped output (gitignored)
├── formalization/             # Alloy models for covenant properties
│   └── alloy/                # .als specs per covenant + cross-covenant
├── site/                     # Interactive research site (separate repo)
├── simple-ctv-vault/         # CTV vault (upstream clone)
├── pymatt/                   # CCV vault (upstream clone)
└── simple-op-vault/          # OP_VAULT demo (upstream clone)
```

## Setup

Requires vault implementations as siblings:

```bash
# Clone upstream repos
git clone https://github.com/AlejandroAkbal/simple-ctv-vault.git
git clone https://github.com/Merkleize/pymatt.git
git clone https://github.com/jamesob/opvault-demo.git simple-op-vault
```

Install dependencies:

```bash
cd vault-comparison
uv pip install -e ".[ctv,ccv]"
```

For OP_VAULT, install its dependencies separately:

```bash
cd simple-op-vault
pip install -r requirements.txt
```

## Node Requirements

Each adapter requires a specific Bitcoin node variant. Clone and build all three:

```bash
# CTV — Bitcoin Inquisition
git clone https://github.com/AlejandroAkbal/bitcoin-inquisition.git ~/bitcoin-inquisition
cd ~/bitcoin-inquisition && cmake -B build && cmake --build build -j$(nproc)

# CCV — Merkleize Bitcoin (inq-ccv branch)
git clone -b inq-ccv https://github.com/AlejandroAkbal/merkleize-bitcoin.git ~/merkleize-bitcoin-ccv
cd ~/merkleize-bitcoin-ccv && cmake -B build && cmake --build build -j$(nproc)

# OP_VAULT — jamesob/bitcoin (autotools, not cmake)
git clone -b 2023-02-opvault-inq https://github.com/jamesob/bitcoin.git ~/bitcoin-opvault
cd ~/bitcoin-opvault && ./autogen.sh && ./configure --without-miniupnpc && make -j$(nproc)
```

The `switch-node.sh` script manages starting/stopping nodes and wiping regtest between runs:

- **CTV:** `./switch-node.sh inquisition`
- **CCV:** `./switch-node.sh ccv`
- **OP_VAULT:** `./switch-node.sh opvault`

Switching wipes regtest state. If your node paths differ from the defaults (`~/bitcoin-inquisition`, `~/merkleize-bitcoin-ccv`, `~/bitcoin-opvault`), set the environment overrides documented in `switch-node.sh --help`.

## Usage

The `run` command automatically switches Bitcoin nodes and initializes regtest.

```bash
cd vault-comparison

# List available experiments
uv run run.py list

# Run an experiment on a specific covenant
uv run run.py run lifecycle_costs --covenant ctv
uv run run.py run lifecycle_costs --covenant ccv
uv run run.py run lifecycle_costs --covenant opvault

# Run on all three covenants (CTV → CCV → OP_VAULT)
uv run run.py run lifecycle_costs --covenant all

# Run all core experiments across all covenants
uv run run.py run --tag core --covenant all

# Skip node switching (node already running)
uv run run.py run lifecycle_costs --covenant ctv --no-switch

# View saved results
uv run run.py compare results/<timestamp_directory>
```

## Experiments

The framework includes 12 experiments organized by scope category.

### Category Taxonomy

- **Comparative** — Same test across covenants; finding comes from the difference
- **Capability gap** — Feature that some covenants support and others cannot
- **Covenant-specific** — Tests semantics unique to one covenant design
- **Analytical** — Fee projections and sensitivity analysis (no node required)

### Experiment Catalog

| # | Name | Covenants | Category | Description |
|---|------|-----------|----------|-------------|
| A | `lifecycle_costs` | CTV, CCV, OPV | Comparative | Full vault lifecycle transaction sizes and fees |
| B | `address_reuse` | CTV, CCV, OPV | Comparative | Second-deposit safety: stuck funds (CTV) vs safe re-funding (CCV, OPV) |
| C | `fee_pinning` | CTV, CCV, OPV | Comparative | Fee mechanism and descendant-chain pinning surface |
| D | `recovery_griefing` | CTV, CCV, OPV | Comparative | Forced-recovery griefing: three-way asymmetric cost analysis |
| E | `revault_amplification` | CCV, OPV | Capability gap | Partial withdrawal chaining and cost accumulation |
| F | `multi_input` | CTV, CCV, OPV | Capability gap | Batched trigger efficiency and cross-input accounting |
| G | `ccv_edge_cases` | CCV | CCV-only | Mode confusion, keypath bypass, sentinel values |
| H | `watchtower_exhaustion` | CCV, OPV | Security | Revault-splitting watchtower fee exhaustion attack |
| I | `fee_sensitivity` | All (analytical) | Analytical | Three-way fee environment sensitivity projections |
| J | `opvault_recovery_auth` | OPV | OP_VAULT-specific | Authorized recovery as defense and attack surface |
| K | `opvault_trigger_key_theft` | OPV | OP_VAULT-specific | Trigger key theft: attacker vs watchtower recovery race |
| M | `ccv_mode_bypass` | CCV | CCV-only | Production-shaped vault UTXO theft via OP_SUCCESS on undefined CCV modes |

### Key Security Findings

The three-way comparison reveals a distinct vulnerability profile for each covenant:

**CTV** — Hot key compromise leads to fund theft (delayed by timelock). Fee pinning via anchor outputs. No revault means no splitting attacks. Address reuse causes permanent fund loss.

**CCV** — Keyless recovery griefing (anyone can force-recover, lowest attacker bar). Watchtower fee exhaustion via revault splitting. No fee pinning (no anchor outputs). Safe address reuse. **Critical: undefined CCV mode values (TM8) cause OP_SUCCESS — complete covenant bypass, full vault theft with no signature required.**

**OP_VAULT** — Authorized recovery blocks keyless griefing (requires recoveryauth key). Same revault-splitting vulnerability as CCV. Fee-input model eliminates pinning. Safe address reuse. Trigger key theft mitigated by watchtower + authorized recovery race.

### Running by Category

```bash
cd vault-comparison

# All comparative experiments across covenants
uv run run.py run --tag comparative --covenant all

# Security-focused experiments
uv run run.py run --tag security --covenant all

# OP_VAULT-specific experiments
uv run run.py run --tag opvault_specific --covenant opvault

# Capability-gap experiments
uv run run.py run --tag capability_gap --covenant all

# CCV-only edge cases
uv run run.py run --tag ccv_only --covenant ccv

# Quantitative cost experiments
uv run run.py run --tag quantitative --covenant all

# Run everything
uv run run.py run --all --covenant all
```

## Adapter Capabilities

Each adapter exposes the vault lifecycle through a common interface. Some capabilities are covenant-specific:

| Capability | CTV | CCV | OP_VAULT |
|-----------|-----|-----|----------|
| `create_vault()` | Yes | Yes | Yes |
| `trigger_unvault()` | Yes | Yes | Yes |
| `complete_withdrawal()` | Yes | Yes | Yes |
| `trigger_recovery()` | Yes | Yes | Yes (authorized) |
| `trigger_revault()` | No | Yes | Yes |
| `trigger_batched()` | No | Yes | Yes |
| Address reuse safe | No | Yes | Yes |
| Fee mechanism | Anchor output | No anchors | Fee input |

## Analysis Pipeline

After running experiments, generate a consolidated analysis report:

```bash
cd vault-comparison

# Run everything and generate the report in one step
bash run_full.sh

# Or generate from an existing results directory
uv run analyze_results.py results/<timestamp_directory>
```

This produces `full_analysis.md` with lifecycle costs, security findings, capability comparisons, threat matrix, and key numbers. The report includes standardized regtest caveats separating structural measurements (vsize, valid on mainnet) from economic dynamics (fees, regtest-only).

## Output Structure

Results are saved to timestamped directories under `vault-comparison/results/`:

```
results/2026-02-21_143000/
├── lifecycle_costs/
│   ├── ctv.json          # Raw ExperimentResult
│   ├── ccv.json
│   ├── opvault.json
│   ├── comparison.json   # Side-by-side data
│   └── summary.md        # Markdown comparison table
├── multi_input/
│   ├── scaling_ctv.csv   # For plotting
│   ├── scaling_ccv.csv
│   └── scaling_comparison.md
└── ...
```

## Memory Layer

A SQLite-based research memory system tracks findings across sessions:

```bash
python memory/research_memory.py summary                    # Overall progress
python memory/research_memory.py search "fee pinning"       # Full-text search
python memory/research_memory.py list-attacks --covenant CTV
python memory/research_memory.py list-questions --status open
```

## Formalization

Alloy models in `formalization/alloy/` specify covenant properties (fund conservation, recovery guarantees, no-extraction invariants) and cross-covenant comparisons. Run all specs:

```bash
cd formalization/alloy
bash run_all.sh
```

## Site

An interactive research site lives in `site/` with its own git repo. It presents the threat models, measured evidence, and cross-covenant comparisons from the experiments. Hosted at [research.praneethg.xyz](https://research.praneethg.xyz).

## Further Reading

- `DESIGN.md` — Architecture, adapter pattern, threat model methodology, full experiment catalog with threat models, regtest limitations
- `REFERENCES.md` — Prior art survey with per-experiment attribution (BIPs 119, 345, 443; Swambo et al.; Harding's watchtower analysis)

## Credits

This work builds on vault implementations and covenant proposals by:

- **Jeremy Rubin** — OP_CHECKTEMPLATEVERIFY (BIP-119) and the CTV vault design
- **Salvatore Ingala** — OP_CHECKCONTRACTVERIFY (BIP-443), the MATT framework, and the `pymatt` vault implementation
- **James O'Beirne** — OP_VAULT (BIP-345) and the `opvault-demo` reference implementation

See `REFERENCES.md` for the full prior art survey.
