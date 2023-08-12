FROM        debian:buster-slim

RUN         apt-get update \
            && apt-get install -y --no-install-recommends ca-certificates libssl-dev glibc \
            && apt-get clean \
            && rm -rf /var/lib/apt/lists/*

ENV         TINI_VERSION v0.19.0

ADD         https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static /tini
RUN         chmod +x /tini

COPY        target/release/myeth-id /bin/myeth-id

ENTRYPOINT  ["/tini", "--"]
CMD         ["/bin/myeth-id"]
