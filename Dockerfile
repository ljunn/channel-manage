FROM node:20-alpine AS web
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM golang:1.23-alpine AS server
ARG VERSION=dev
ARG BUILD_TYPE=development
ARG GITHUB_REPO=ljunn/channel-manage
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
COPY --from=web /src/frontend/dist/ ./cmd/server/web/dist/
RUN RELEASE_VERSION="${VERSION#v}" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=${RELEASE_VERSION} -X main.BuildType=${BUILD_TYPE} -X main.GitHubRepo=${GITHUB_REPO}" -o /out/channel-manage ./cmd/server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && addgroup -S app && adduser -S -G app app
COPY --from=server /out/channel-manage /usr/local/bin/channel-manage
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/channel-manage"]
