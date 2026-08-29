# Build from repo root: docker build -f scanner/Dockerfile -t aegify-scanner .
FROM ghcr.io/astral-sh/uv:0.12.5@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1 AS uv
FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS builder

COPY --from=uv /uv /uvx /bin/

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/aegify
COPY scanner/pyproject.toml scanner/uv.lock scanner/README.md scanner/hatch_build.py ./
COPY scanner/src/ src/
COPY rules/ /opt/rules/
RUN uv sync --locked --no-dev --no-editable

FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4

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
