# Build stage runs natively on the builder's arch (BUILDPLATFORM) and
# cross-compiles to TARGETPLATFORM. This avoids QEMU emulating `go build`,
# which is the slow part of multiarch builds (~10x speedup for arm64).
FROM --platform=$BUILDPLATFORM golang:1.23-alpine3.20 AS build

RUN apk add --no-cache git

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -o webhook -ldflags '-w -s -extldflags "-static"' .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
