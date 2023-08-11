FROM alpine:latest

RUN apk update --quiet \
&& apk add -q --no-cache libgcc tini curl

COPY target/x86_64-unknown-linux-musl/release/myeth-id /bin/myeth-id
RUN ln -s /bin/myeth-id /myeth-id

ENTRYPOINT ["myeth-id"]
