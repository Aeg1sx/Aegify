# Build from repo root: docker build -f scanner/Dockerfile -t aegify-scanner .
FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS builder

COPY --from=uv /uv /uvx /bin/

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/aegify
COPY scanner/pyproject.toml scanner/uv.lock scanner/README.md scanner/hatch_build.py ./
COPY scanner/src/ src/
COPY rules/ /opt/rules/
RUN uv sync --locked --no-dev --no-editable

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# git is needed for scan-pr (computing diffs)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    git config --system --add safe.directory '*' && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 10001 aegify && \
    useradd --system --uid 10001 --gid 10001 --home-dir /scan --shell /usr/sbin/nologin aegify

COPY --from=builder /opt/aegify/.venv /opt/aegify/.venv
ENV PATH="/opt/aegify/.venv/bin:${PATH}"

WORKDIR /scan
USER 10001:10001
ENTRYPOINT ["aegify"]
CMD ["--help"]
