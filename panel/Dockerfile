# Builds on the host architecture; no ARM emulator is needed.
FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build
ARG TARGETARCH
ARG TARGETVARIANT
ARG AWG_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e
RUN apk add --no-cache git
WORKDIR /engine
RUN git init && git remote add origin https://github.com/amnezia-vpn/amneziawg-go.git && \
    git fetch --depth=1 origin ${AWG_COMMIT} && git checkout --detach FETCH_HEAD
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH GOARM=7 \
    go build -trimpath -ldflags="-s -w" -o /amneziawg-go .
WORKDIR /src
COPY go.mod *.go ./
COPY web ./web
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH GOARM=7 \
    go build -trimpath -ldflags="-s -w" -o /awg-control .

FROM --platform=$BUILDPLATFORM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS packages
ARG TARGETARCH
RUN case "$TARGETARCH" in arm) arch=armv7;; arm64) arch=aarch64;; amd64) arch=x86_64;; *) exit 1;; esac; \
    cp -L /usr/share/apk/keys/"$arch"/* /etc/apk/keys/; \
    mkdir -p /rootfs/etc/apk; cp -a /etc/apk/keys /rootfs/etc/apk/keys; \
    apk --root /rootfs --arch "$arch" --initdb --no-scripts \
        --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories \
        add --no-cache iproute2 iptables iptables-legacy

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=packages /rootfs/ /
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /amneziawg-go /usr/bin/amneziawg-go
COPY --from=build /engine/LICENSE /usr/share/licenses/amneziawg-go/LICENSE
COPY --from=build /awg-control /awg-control
ENV GOMEMLIMIT=8MiB GOGC=30 GOMAXPROCS=1
EXPOSE 8088
STOPSIGNAL SIGTERM
ENTRYPOINT ["/awg-control"]
