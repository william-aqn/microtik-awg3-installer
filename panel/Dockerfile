FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /src
COPY go.mod *.go ./
COPY web ./web
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH GOARM=7 go build -trimpath -ldflags="-s -w" -o /awg-panel .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /awg-panel /awg-panel
ENV GOMEMLIMIT=8MiB GOGC=30 GOMAXPROCS=1
EXPOSE 8088
ENTRYPOINT ["/awg-panel"]
