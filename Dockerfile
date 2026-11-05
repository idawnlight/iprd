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

FROM --platform=$BUILDPLATFORM alpine:3.24 AS coreadi
RUN wget -qO /tmp/applemusic.apk https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk && \
    mkdir -p /out/amd64 /out/arm64 && \
    unzip -q -j /tmp/applemusic.apk "lib/x86_64/libCoreADI.so" "lib/x86_64/libstoreservicescore.so" -d /out/amd64 && \
    unzip -q -j /tmp/applemusic.apk "lib/arm64-v8a/libCoreADI.so" "lib/arm64-v8a/libstoreservicescore.so" -d /out/arm64 && \
    rm -f /tmp/applemusic.apk

FROM dadoum/anisette-v3-server:latest
ARG TARGETARCH
USER root
WORKDIR /app
COPY --from=build /out/iprd /usr/local/bin/iprd
COPY --from=coreadi /out/${TARGETARCH}/ /opt/anisette-v3/lib/
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENV RUNTIME_DIRECTORY=/tmp \
    IPRD_ANISETTE_SERVER=http://127.0.0.1:6969 \
    IPRD_ANISETTE_STATE=/tmp/anisette-local
EXPOSE 1080
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
