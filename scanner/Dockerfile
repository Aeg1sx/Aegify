# Build from repo root: docker build -f scanner/Dockerfile -t aegify-scanner .
FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build/scanner
COPY scanner/pyproject.toml scanner/README.md ./
COPY scanner/src/ src/
COPY rules/ /build/rules/
RUN pip install --no-cache-dir --no-compile .

FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

# git is needed for scan-pr (computing diffs)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    git config --system --add safe.directory '*' && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 10001 aegify && \
    useradd --system --uid 10001 --gid 10001 --home-dir /scan --shell /usr/sbin/nologin aegify

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/aegify /usr/local/bin/aegify

WORKDIR /scan
USER 10001:10001
ENTRYPOINT ["aegify"]
CMD ["--help"]
