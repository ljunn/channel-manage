# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM node:20-alpine AS web
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS server
ARG VERSION=dev
ARG BUILD_TYPE=development
ARG GITHUB_REPO=ljunn/channel-manage
ARG TARGETOS
ARG TARGETARCH=amd64
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
COPY --from=web /src/frontend/dist/ ./cmd/server/web/dist/
RUN RELEASE_VERSION="${VERSION#v}" && CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH}" go build -trimpath -ldflags="-s -w -X main.Version=${RELEASE_VERSION} -X main.BuildType=${BUILD_TYPE} -X main.GitHubRepo=${GITHUB_REPO}" -o /out/channel-manage ./cmd/server

FROM --platform=$BUILDPLATFORM alpine:3.21 AS runtime-files
RUN apk add --no-cache ca-certificates tzdata && addgroup -S app && adduser -S -G app app

FROM alpine:3.21
COPY --from=runtime-files /etc/passwd /etc/passwd
COPY --from=runtime-files /etc/group /etc/group
COPY --from=runtime-files /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-files /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=server /out/channel-manage /usr/local/bin/channel-manage
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/channel-manage"]
