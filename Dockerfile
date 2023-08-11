FROM alpine:latest

RUN apk update --quiet \
&& apk add -q --no-cache libgcc tini curl

COPY target/x86_64-unknown-linux-musl/release/app /bin/app
RUN ln -s /bin/app /app

ENTRYPOINT ["app"]