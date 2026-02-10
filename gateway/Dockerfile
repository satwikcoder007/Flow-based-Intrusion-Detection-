FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PCAP_DIR=/app/data/pcaps
ENV FLOW_DIR=/app/data/flows
ENV FLOW_ARCHIVE_DIR=/app/data/flows_archive

# Install system tools needed for packet capture
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    iproute2 \
    net-tools \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps for your gateway
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install CICFlowMeter
RUN git clone https://github.com/hieulw/cicflowmeter.git /opt/cicflowmeter
WORKDIR /opt/cicflowmeter
RUN pip install .

# Create data folders
WORKDIR /app
RUN mkdir -p ${PCAP_DIR} ${FLOW_DIR} ${FLOW_ARCHIVE_DIR}

# Copy your app
COPY gateway.py .
COPY run.sh .
RUN chmod +x run.sh

CMD ["bash", "run.sh"]
