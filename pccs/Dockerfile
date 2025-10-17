FROM ubuntu:jammy

# --- Stage 1: Environment Setup ---
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /opt/intel/pccs

# Install minimal dependencies + Node.js 20
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# --- Stage 2: Install Intel PCCS ---
# Download and extract PCCS deb directly (no need to install system-wide)
ARG PCCS_VERSION=1.23.100.0-jammy1
RUN wget -q https://download.01.org/intel-sgx/sgx_repo/ubuntu/pool/main/web/sgx-dcap-pccs/sgx-dcap-pccs_${PCCS_VERSION}_amd64.deb -O /tmp/pccs.deb && \
    dpkg-deb -x /tmp/pccs.deb /tmp/pccs && \
    cp -r /tmp/pccs/opt/intel/sgx-dcap-pccs/* /opt/intel/pccs && \
    rm -rf /tmp/pccs*

RUN npm install --omit=dev

# Copy setup script (entrypoint)
COPY setup.sh ./setup.sh
RUN chmod +x ./setup.sh

# Create non-root user for PCCS
ARG USER=pccs
ARG UID=65333
RUN useradd -r -u ${UID} -s /usr/sbin/nologin ${USER} && \
    chown -R ${USER}:${USER} /opt/intel/pccs

USER ${USER}

ENTRYPOINT ["sh","setup.sh"]
