FROM ubuntu:22.04

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Define environment variables required for pcap and flow files
ENV PCAP_DIR=/app/data/pcaps
ENV FLOW_DIR=/app/data/flows

# 1. Install System Dependencies
# We keep libpcap-dev because the python wrapper still needs the C libraries
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libpcap-dev \
    tcpdump \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# 3. Setup directories for IDS data
RUN mkdir -p ${PCAP_DIR} ${FLOW_DIR}

# 4. Copy application code
COPY gateway.py .
COPY run.sh .
# COPY model.pkl .

# Ensure run.sh is executable
RUN chmod +x run.sh

CMD ["bash", "run.sh"]