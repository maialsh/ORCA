FROM ubuntu:22.04

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies and analysis tools
RUN apt-get update -y && \
    apt-get install -y \
        build-essential \
        python3-dev \
        python3-pip \
        binutils \
        strace \
        file \
        libffi-dev \
        libssl-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        libjpeg-dev \
        libpq-dev \
        git && \
    python3 -m pip install --no-cache-dir --upgrade pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Create a writable tmp directory for analysis
RUN chmod 777 /tmp

# Default command (will be overridden by sandbox.py)
CMD ["sleep", "infinity"]
