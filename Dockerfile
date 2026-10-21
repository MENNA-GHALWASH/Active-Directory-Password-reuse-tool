# ad-reuse-tool image — Python 3.11 + impacket.
#
# NOTE: The working pipeline runs on the host, not in this image.
# password_reuse.sh calls `docker exec samba-dc pdbedit`, which
# requires the Docker CLI on the host. This image is provided for
# teammates who want to run parse_hashes.py in a consistent env.

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libkrb5-3 libssl3 dnsutils iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir impacket

WORKDIR /app
COPY password_reuse.sh parse_hashes.py ./
RUN chmod +x password_reuse.sh

ENTRYPOINT ["/bin/bash"]
