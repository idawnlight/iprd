# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/iprd ./cmd/iprd

FROM dadoum/anisette-v3-server:latest
USER root
WORKDIR /app
COPY --from=build /out/iprd /usr/local/bin/iprd
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN mkdir -p /app/runtime && chown -R Alcoholic:Alcoholic /app
USER Alcoholic
ENV RUNTIME_DIRECTORY=/app/runtime \
    IPRD_ANISETTE_SERVER=http://127.0.0.1:6969 \
    IPRD_ANISETTE_STATE=/app/runtime/anisette-local
EXPOSE 1080
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
