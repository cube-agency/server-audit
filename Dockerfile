FROM anchore/grype:v0.121.0 AS grype

FROM alpine:3.24
RUN apk upgrade --no-cache && \
    apk add --no-cache \
    bash \
    ca-certificates \
    coreutils \
    jq \
    openssh-client \
    tar

COPY --from=grype /grype /usr/local/bin/grype
COPY server-audit.sh check-restarts.sh summary.jq /opt/server-audit/
RUN ln -s /opt/server-audit/server-audit.sh /usr/local/bin/server-audit \
    && grype version

WORKDIR /work
CMD ["server-audit"]
