FROM docker.io/library/rust@sha256:593db038d36ea0d2e5b22a2e095eb95dbec607d88d658c2f35f65ee880b4f93a AS builder

WORKDIR /src
COPY . .
RUN cargo build -p tomorrowci-cli --release --locked

FROM docker.io/library/docker@sha256:be132a9f282288de4afaf63379dff75711fda0147c6b72a9df44e51841402144 AS docker-cli

FROM docker.io/library/debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

ARG TCI_VERSION
ARG TCI_REVISION
ARG TCI_SOURCE=https://github.com/taipei49314/tomorrowci

LABEL org.opencontainers.image.title="TomorrowCI" \
      org.opencontainers.image.description="Evidence-first compatibility frontier scanner" \
      org.opencontainers.image.source="$TCI_SOURCE" \
      org.opencontainers.image.revision="$TCI_REVISION" \
      org.opencontainers.image.version="$TCI_VERSION" \
      org.opencontainers.image.licenses="Apache-2.0"

# The Debian snapshot timestamp is immutable. Package installation remains a
# fetch-stage operation, but the resolved runtime package universe cannot move.
RUN printf '%s\n' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260803T000000Z bookworm main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260803T000000Z bookworm-updates main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260803T000000Z bookworm-security main' \
      > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
         ca-certificates git \
    && rm -rf \
         /var/lib/apt/lists/* \
         /var/cache/apt/* \
         /var/log/apt \
    && rm -f \
         /var/cache/ldconfig/aux-cache \
         /var/log/alternatives.log \
         /var/log/dpkg.log \
    && mkdir -p /home/tomorrowci/.docker /workspace \
    && chown -R 65532:65532 /home/tomorrowci /workspace

COPY --from=builder /src/target/release/tomorrowci /usr/local/bin/tomorrowci
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

ENV HOME=/home/tomorrowci \
    DOCKER_CONFIG=/home/tomorrowci/.docker
WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tomorrowci"]
CMD ["--help"]
