.PHONY: run test tidy migrate
tidy:    ; go mod tidy
run:     ; set -a; . ./.env; set +a; go run ./cmd/server
test:    ; go test ./... -race -count=1
migrate: ; set -a; . ./.env; set +a; psql "$$DATABASE_URL" -f migrations/001_init.sql
