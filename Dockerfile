# ThreatChain -- self-contained image. Every scanner (Semgrep, Gitleaks, Trivy,
# Nuclei, PMD) and the CodeQL bundle are baked in, so a new machine needs only
# Docker: no setup_all.py, no Java install, no venv.
#
#   docker compose up --build        # then open http://127.0.0.1:8765
#   docker build -t threatchain .    # plain build without compose
#
# Pinned to linux/amd64 on purpose: the CodeQL bundle is x86_64-only, so pinning
# the whole image keeps every tool on one architecture (it runs under emulation
# on Apple Silicon / arm64 hosts).
FROM --platform=linux/amd64 python:3.14-slim-bookworm

# git             -- remote-repo scans, Gitleaks history, Semgrep rule-pack fetch
# default-jre     -- PMD (Apex / Java rules)
# ca-certificates -- TLS to OSV / NVD and the tool download hosts
# curl/unzip/tar/xz -- the tool installers fetch and extract releases
RUN apt-get -o Acquire::Retries=5 update \
 && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
      git default-jre-headless ca-certificates curl unzip tar xz-utils \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Bake the scanners + pinned rule pack into the image. setup_all.py also pre-fetches
# the Trivy vulnerability DB, so the first image scan is fast. Any failed tool makes
# setup_all exit non-zero, which fails the build on purpose: a complete image is the
# whole point. Its own layer so a CodeQL retry below reuses this ~25-minute step.
# Retried: on a flaky network a single tool download can blip, and a re-run installs
# only what is still missing (setup_all skips tools already in place).
RUN for i in 1 2 3; do \
      python3 setup_all.py && break || { echo "setup_all urinish $i muvaffaqiyatsiz, qayta…"; sleep 5; }; \
    done; \
    python3 setup_all.py

# CodeQL (~0.9 GB) deep analysis, in its own layer. On by default; build with
#   --build-arg WITH_CODEQL=0
# to skip it on a slow or constrained network and add it later inside the running
# container (`docker exec <container> python3 setup_codeql.py`). The six core stages
# (code, repository, dependencies, images, iac, web) and every chain rule work
# without it. Retried: the download can truncate under emulation and the SHA-256
# check then rejects the partial file; a still-missing CodeQL fails the build rather
# than shipping a half-installed image.
ARG WITH_CODEQL=1
RUN if [ "$WITH_CODEQL" = "1" ]; then \
      for i in 1 2 3; do \
        python3 setup_codeql.py && break || { echo "CodeQL urinish $i muvaffaqiyatsiz, qayta…"; sleep 5; }; \
      done; \
      test -x .tools/codeql/codeql/codeql; \
    else \
      echo "CodeQL o‘tkazib yuborildi (WITH_CODEQL=0). Keyin: docker exec <konteyner> python3 setup_codeql.py"; \
    fi

# The server binds 0.0.0.0 so Docker's port forwarder can reach it; the published
# port is mapped only to the host loopback (see docker-compose.yml), so nothing on
# the network can reach it. THREATCHAIN_TRUST_BIND makes that intent explicit --
# see the comment in app.py make_server().
ENV THREATCHAIN_TRUST_BIND=1
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/api/readiness',timeout=3).status==200 else 1)"

CMD ["python3", "app.py", "--bind", "0.0.0.0", "--port", "8765"]
