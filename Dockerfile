# ============================================================
# Bitcoin Covenant Vault Comparison — Multi-stage Docker Build
# ============================================================
# Builds all 3 Bitcoin node variants + Python framework in one image.
# With BuildKit, stages 2-4 build in parallel.
# Requires ~8 GB Docker memory (Settings → Resources).
#
#   docker build -t vault-comparison .
#
# ============================================================

# ── Stage 1: Base ────────────────────────────────────────────
FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    # C++ build toolchain
    build-essential cmake autoconf automake libtool pkg-config \
    # Bitcoin node dependencies
    libssl-dev libboost-all-dev libevent-dev libsqlite3-dev libzstd-dev \
    # Python
    python3 python3-dev python3-pip python3-venv \
    # Utilities
    git curl jq \
    && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager)
RUN pip3 install --no-cache-dir uv

# ── Stage 2: Bitcoin Inquisition (CTV) ──────────────────────
FROM base AS build-inquisition

RUN git clone --depth 1 --single-branch \
    https://github.com/bitcoin-inquisition/bitcoin.git /src/bitcoin-inquisition

WORKDIR /src/bitcoin-inquisition
RUN cmake -B build -DBUILD_TESTING=OFF -DBUILD_BENCH=OFF \
    && cmake --build build -j4

RUN mkdir -p /opt/bitcoin-inquisition \
    && cp build/bin/bitcoind build/bin/bitcoin-cli /opt/bitcoin-inquisition/

# ── Stage 3: Merkleize Bitcoin (CCV) ────────────────────────
FROM base AS build-ccv

RUN git clone --depth 1 --single-branch -b inq-ccv \
    https://github.com/Merkleize/bitcoin.git /src/merkleize-bitcoin-ccv

WORKDIR /src/merkleize-bitcoin-ccv
RUN cmake -B build -DBUILD_TESTING=OFF -DBUILD_BENCH=OFF \
    && cmake --build build -j4

RUN mkdir -p /opt/merkleize-bitcoin-ccv \
    && cp build/bin/bitcoind build/bin/bitcoin-cli /opt/merkleize-bitcoin-ccv/

# ── Stage 4: OP_VAULT (jamesob/bitcoin) ─────────────────────
FROM base AS build-opvault

RUN git clone --depth 1 --single-branch -b 2023-02-opvault-inq \
    https://github.com/jamesob/bitcoin.git /src/bitcoin-opvault

WORKDIR /src/bitcoin-opvault
RUN ./autogen.sh \
    && ./configure --without-miniupnpc --without-gui --disable-tests --disable-bench \
    && make -j4

RUN mkdir -p /opt/bitcoin-opvault \
    && cp src/bitcoind src/bitcoin-cli /opt/bitcoin-opvault/

# ── Stage 5: Final ──────────────────────────────────────────
FROM base AS final

# Copy node binaries from build stages
COPY --from=build-inquisition /opt/bitcoin-inquisition /opt/bitcoin-inquisition
COPY --from=build-ccv /opt/merkleize-bitcoin-ccv /opt/merkleize-bitcoin-ccv
COPY --from=build-opvault /opt/bitcoin-opvault /opt/bitcoin-opvault

# Create workspace
WORKDIR /workspace

# Clone upstream vault implementations
RUN git clone --depth 1 https://github.com/jamesob/simple-ctv-vault.git \
    && git clone --depth 1 https://github.com/Merkleize/pymatt.git \
    && git clone --depth 1 https://github.com/jamesob/opvault-demo.git simple-op-vault \
    && git clone --depth 1 https://github.com/PraneethGunas/cat-csfs-vault.git simple-cat-csfs-vault

# Copy framework source
COPY vault-comparison/ vault-comparison/
COPY switch-node.sh .
COPY entrypoint.sh .
RUN chmod +x switch-node.sh entrypoint.sh

# Enable RIPEMD-160 (disabled by default in OpenSSL 3.x, needed by buidl/python-bitcoinlib)
RUN sed -i '1s/^/openssl_conf = openssl_init\n/' /etc/ssl/openssl.cnf \
    && printf '\n[openssl_init]\nproviders = provider_sect\n[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n[default_sect]\nactivate = 1\n[legacy_sect]\nactivate = 1\n' >> /etc/ssl/openssl.cnf

# Install Python dependencies via uv (cached at build time so runtime is fast)
RUN cd vault-comparison && uv sync --extra all \
    && cd ../pymatt && uv sync --extra examples \
    && pip3 install --no-cache-dir -r ../simple-op-vault/requirements.txt

# Write pymatt .env for RPC
RUN printf 'RPC_HOST=localhost\nRPC_USER=rpcuser\nRPC_PASSWORD=rpcpass\nRPC_PORT=18443\n' > pymatt/.env

# Write bitcoin.conf for regtest
RUN mkdir -p /root/.bitcoin && printf '\
    regtest=1\n\
    server=1\n\
    txindex=1\n\
    fallbackfee=0.00001\n\
    minrelaytxfee=0\n\
    blockmintxfee=0\n\
    acceptnonstdtxn=1\n\
    [regtest]\n\
    rpcuser=rpcuser\n\
    rpcpassword=rpcpass\n\
    rpcport=18443\n\
    rpcbind=0.0.0.0\n\
    rpcallowip=0.0.0.0/0\n' > /root/.bitcoin/bitcoin.conf

# Set node path env vars for switch-node.sh
ENV INQUISITION_BIN=/opt/bitcoin-inquisition/bitcoind \
    INQUISITION_CLI=/opt/bitcoin-inquisition/bitcoin-cli \
    CCV_BIN=/opt/merkleize-bitcoin-ccv/bitcoind \
    CCV_CLI=/opt/merkleize-bitcoin-ccv/bitcoin-cli \
    OPVAULT_BIN=/opt/bitcoin-opvault/bitcoind \
    OPVAULT_CLI=/opt/bitcoin-opvault/bitcoin-cli \
    BITCOIN_DATADIR=/root/.bitcoin

# RPC defaults
ENV RPC_HOST=localhost \
    RPC_PORT=18443 \
    RPC_USER=rpcuser \
    RPC_PASSWORD=rpcpass

# Results volume
VOLUME /data/results

EXPOSE 18443

ENTRYPOINT ["/workspace/entrypoint.sh"]
CMD ["--help"]
