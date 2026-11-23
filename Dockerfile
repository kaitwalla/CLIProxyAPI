FROM golang:1.26-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends build-essential git curl ca-certificates && rm -rf /var/lib/apt/lists/*

# Pin the management frontend independently of the server release.
RUN mkdir -p /panel && curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --retry 3 \
    https://github.com/router-for-me/Cli-Proxy-API-Management-Center/releases/download/v1.29.1/management.html \
    -o /panel/management.html && \
    echo '30df9503402af03e04affb55920458c13139a07757c8428fc845299876d19c43  /panel/management.html' | sha256sum -c -

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=1 GOOS=linux go build -buildvcs=false -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.Commit=${COMMIT}' -X 'main.BuildDate=${BUILD_DATE}'" -o ./CLIProxyAPI ./cmd/server/

FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends tzdata ca-certificates && rm -rf /var/lib/apt/lists/*

RUN mkdir /CLIProxyAPI

COPY --from=builder ./app/CLIProxyAPI /CLIProxyAPI/CLIProxyAPI

COPY config.example.yaml /CLIProxyAPI/config.example.yaml
COPY --from=builder /panel/management.html /CLIProxyAPI/static/management.html
ENV MANAGEMENT_STATIC_PATH=/CLIProxyAPI/static/management.html

WORKDIR /CLIProxyAPI

EXPOSE 8317

ENV TZ=Asia/Shanghai

RUN cp /usr/share/zoneinfo/${TZ} /etc/localtime && echo "${TZ}" > /etc/timezone

CMD ["./CLIProxyAPI"]
