# Empirical Comparison of Bitcoin Covenant Vault Designs

Comparative analysis framework for CTV (BIP-119), CCV (BIP-443), OP_VAULT (BIP-345), and CAT+CSFS (BIP-347 + BIP-348) vault implementations on Bitcoin regtest.

## Overview

This framework runs side-by-side experiments against four covenant vault implementations, measuring transaction costs, security properties, and capability differences. Each experiment produces on-chain measurements from regtest, not simulated or estimated values.

The four covenant proposals represent fundamentally different design philosophies for Bitcoin vaults: CTV commits to exact transaction templates at vault creation; CCV enforces contract rules dynamically at spend time; OP_VAULT provides purpose-built vault opcodes with authorized recovery and dynamic withdrawal targets; CAT+CSFS uses generic stack introspection (OP_CAT) with signature-from-stack verification (OP_CHECKSIGFROMSTACK) to enforce vault transitions via dual-key signing.

## Repository Layout

```
research experiments/
├── README.md                 # This file
├── REFERENCES.md             # Prior art and per-experiment citations
├── DESIGN.md                 # Architecture, threat models, experiment catalog
├── Dockerfile                # Multi-stage build (Bitcoin nodes + framework)
├── docker-compose.yml        # Single-command experiment runner
├── Makefile                  # Build/run/test/analyze shortcuts
├── entrypoint.sh             # Docker entrypoint with --help
├── switch-node.sh            # Node manager (Inquisition / CCV / OP_VAULT)
├── vault-comparison/         # Framework source
│   ├── run.py                # CLI runner
│   ├── run_full.sh           # Full pipeline (run all → analyze)
│   ├── analyze_results.py    # Consolidated report generator
│   ├── config.py             # Centralized configuration (FeeConstants, FrameworkConfig)
│   ├── config.toml           # Tunable parameters (fee rates, paths, delays)
│   ├── harness/              # Shared infra (RPC, metrics, reporting, logging, coin pool)
│   ├── adapters/             # Vault drivers (CTV, CCV, OP_VAULT, CAT+CSFS)
│   ├── experiments/          # Experiment modules (16 experiments)
│   ├── tests/                # Unit tests (pytest) and integration tests
│   └── results/              # Timestamped output (gitignored)
├── formalization/             # Alloy models for covenant properties
│   └── alloy/                # .als specs per covenant + cross-covenant
├── site/                     # Interactive research site (separate repo)
├── simple-ctv-vault/         # CTV vault (upstream clone)
├── simple-cat-csfs-vault/    # CAT+CSFS vault (custom implementation)
├── pymatt/                   # CCV vault (upstream clone)
└── simple-op-vault/          # OP_VAULT demo (upstream clone)
```

## Quick Start (Docker)

The fastest way to run everything. Builds the Bitcoin nodes and the Python framework in a single image.

```bash
# Build (~45 min first time, cached after that)
make build

# Run a single experiment
make lifecycle COVENANT=ctv

# Run all core experiments across all covenants
make run-all

# List available experiments and tags
make list

# Interactive shell inside the container
make shell
```

Requires Docker with at least 8 GB memory (Docker Desktop → Settings → Resources).

Results are mounted to `./results/` on your host. See `make help` for all targets, or `docker run --rm vault-comparison --help` for the full command reference.

## Manual Setup

If you prefer running without Docker, clone the upstream repos and build the nodes yourself.

### Dependencies

```bash
# Clone upstream repos
git clone https://github.com/jamesob/simple-ctv-vault.git
git clone https://github.com/Merkleize/pymatt.git
git clone https://github.com/jamesob/opvault-demo.git simple-op-vault
```

Install Python dependencies:

```bash
cd vault-comparison
uv sync --extra all
```

For OP_VAULT, install its dependencies separately:

```bash
pip install -r simple-op-vault/requirements.txt
```

### Node Requirements

Each adapter requires a specific Bitcoin node variant. CTV and CAT+CSFS share Bitcoin Inquisition; CCV and OP_VAULT each need their own. Clone and build:

```bash
# CTV — Bitcoin Inquisition
git clone https://github.com/bitcoin-inquisition/bitcoin.git ~/bitcoin-inquisition
cd ~/bitcoin-inquisition && cmake -B build && cmake --build build -j$(nproc)

# CCV — Merkleize Bitcoin (inq-ccv branch)
git clone -b inq-ccv https://github.com/Merkleize/bitcoin.git ~/merkleize-bitcoin-ccv
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

# Run on all covenants (CTV → CCV → OP_VAULT → CAT+CSFS)
uv run run.py run lifecycle_costs --covenant all

# Run all core experiments across all covenants
uv run run.py run --tag core --covenant all

# Skip node switching (node already running)
uv run run.py run lifecycle_costs --covenant ctv --no-switch

# View saved results
uv run run.py compare results/<timestamp_directory>
```

## Experiments

The framework includes 16 experiments organized by scope category.

### Category Taxonomy

- **Comparative** — Same test across covenants; finding comes from the difference
- **Capability gap** — Feature that some covenants support and others cannot
- **Covenant-specific** — Tests semantics unique to one covenant design
- **Analytical** — Fee projections and sensitivity analysis (no node required)

### Experiment Catalog

| # | Name | Covenants | Category | Description |
|---|------|-----------|----------|-------------|
| A | `lifecycle_costs` | CTV, CCV, OPV, CAT | Comparative | Full vault lifecycle transaction sizes and fees |
| B | `address_reuse` | CTV, CCV, OPV, CAT | Comparative | Second-deposit safety: stuck funds (CTV) vs safe re-funding (CCV, OPV, CAT) |
| C | `fee_pinning` | CTV, CCV, OPV, CAT | Comparative | Fee mechanism and descendant-chain pinning surface |
| D | `recovery_griefing` | CTV, CCV, OPV, CAT | Comparative | Forced-recovery griefing: four-way asymmetric cost analysis |
| E | `revault_amplification` | CCV, OPV | Capability gap | Partial withdrawal chaining and cost accumulation |
| F | `multi_input` | CTV, CCV, OPV, CAT | Capability gap | Batched trigger efficiency and cross-input accounting |
| G | `ccv_edge_cases` | CCV | CCV-only | Mode confusion, keypath bypass, sentinel values |
| H | `watchtower_exhaustion` | CCV, OPV | Security | Revault-splitting watchtower fee exhaustion attack |
| I | `fee_sensitivity` | All (analytical) | Analytical | Four-way fee environment sensitivity projections |
| J | `opvault_recovery_auth` | OPV | OP_VAULT-specific | Authorized recovery as defense and attack surface |
| K | `opvault_trigger_key_theft` | OPV | OP_VAULT-specific | Trigger key theft: attacker vs watchtower recovery race |
| L | `ccv_mode_bypass` | CCV | CCV-only | Production-shaped vault UTXO theft via OP_SUCCESS on undefined CCV modes |
| M | `cat_csfs_hot_key_theft` | CAT | CAT+CSFS-only | Hot key compromise: griefing-only, no theft path |
| N | `cat_csfs_witness_manipulation` | CAT | CAT+CSFS-only | Witness tampering against OP_CAT+CSFS introspection |
| O | `cat_csfs_destination_lock` | CAT | CAT+CSFS-only | Destination address locking via embedded commitments |
| P | `cat_csfs_cold_key_recovery` | CAT | CAT+CSFS-only | Unconstrained cold key recovery: defense and risk |

### Key Security Findings

The four-way comparison reveals a distinct vulnerability profile for each covenant:

**CTV** — Hot key compromise leads to fund theft (delayed by timelock). Fee pinning via anchor outputs. No revault means no splitting attacks. Address reuse causes permanent fund loss.

**CCV** — Keyless recovery griefing (anyone can force-recover, lowest attacker bar). Watchtower fee exhaustion via revault splitting. No fee pinning (no anchor outputs). Safe address reuse. **Critical: undefined CCV mode values (TM8) cause OP_SUCCESS — complete covenant bypass, full vault theft with no signature required.**

**OP_VAULT** — Authorized recovery blocks keyless griefing (requires recoveryauth key). Same revault-splitting vulnerability as CCV. Fee-input model eliminates pinning. Safe address reuse. Trigger key theft mitigated by watchtower + authorized recovery race.

**CAT+CSFS** — Strongest hot-key theft resistance (griefing-only, no theft path — attacker can trigger but not redirect funds). Weakest cold-key recovery safety (unconstrained OP_CHECKSIG allows sweeping to any destination). No revault or batched triggers. Fee management via anchor outputs (similar pinning surface to CTV). Safe address reuse.

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

| Capability | CTV | CCV | OP_VAULT | CAT+CSFS |
|-----------|-----|-----|----------|----------|
| `create_vault()` | Yes | Yes | Yes | Yes |
| `trigger_unvault()` | Yes | Yes | Yes | Yes |
| `complete_withdrawal()` | Yes | Yes | Yes | Yes |
| `recover()` | Yes | Yes (keyless) | Yes (authorized) | Yes (cold key) |
| `supports_revault()` | No | Yes | Yes | No |
| `supports_batched_trigger()` | No | Yes | Yes | No |
| `supports_keyless_recovery()` | No | Yes | No | No |
| Address reuse safe | No | Yes | Yes | Yes |
| Fee mechanism | Anchor output | No anchors | Fee input | Anchor output |

## Testing

The framework includes unit tests (no node required) and integration tests (require a running Bitcoin node).

```bash
cd vault-comparison

# Run all unit tests
python -m pytest tests/ -m "not integration"

# Run integration tests (requires running node of the appropriate type)
python -m pytest tests/ -m integration

# Verbose output
python -m pytest tests/ -m "not integration" -v
```

Unit tests cover the harness (metrics, reporting), adapter lifecycle (via MockAdapter), experiment registry, configuration loading, and structured logging. Integration tests exercise the full create→trigger→withdraw→recover lifecycle against each real adapter.

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
