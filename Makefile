.PHONY: web test build compose-check

web:
	cd frontend && npm ci && npm run build
	rm -rf backend/cmd/server/web/dist
	mkdir -p backend/cmd/server/web/dist
	cp -R frontend/dist/. backend/cmd/server/web/dist/

test: web
	cd backend && go test ./...

build: web
	cd backend && CGO_ENABLED=0 go build -trimpath -o ../channel-manage ./cmd/server

compose-check:
	docker compose config >/dev/null
