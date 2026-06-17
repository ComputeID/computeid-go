# ComputeID Go SDK + server.

GO              ?= go
DATABASE_URL    ?= postgres://leadpilot:leadpilot@localhost:5439/computeid?sslmode=disable
TEST_DB_URL     ?= postgres://leadpilot:leadpilot@localhost:5439/computeid_test?sslmode=disable
PORT            ?= 8088
JWT_SECRET      ?= local-dev-secret

# ---- code quality ----

.PHONY: build
build:
	$(GO) build ./...

.PHONY: vet
vet:
	$(GO) vet ./...

# Run only the SDK unit tests (no Postgres required).
.PHONY: test-unit
test-unit:
	COMPUTEID_SKIP_INTEGRATION=1 $(GO) test -race -count=1 ./...

# Run everything, including the server + E2E tests that need real Postgres.
# When sharing one database, -p 1 serializes the two test binaries so they
# don't race each other on schema resets.
.PHONY: test
test:
	COMPUTEID_TEST_DATABASE_URL=$(TEST_DB_URL) \
	$(GO) test -race -count=1 -p 1 ./...

# Just the integration / E2E tests.
.PHONY: test-integration
test-integration:
	COMPUTEID_TEST_DATABASE_URL=$(TEST_DB_URL) \
	$(GO) test -race -count=1 -p 1 ./server/... ./...

# ---- local Postgres helpers (against the existing leadpilot db on :5439) ----

.PHONY: db-up
db-up:
	@PGPASSWORD=leadpilot psql -h localhost -p 5439 -U leadpilot -d postgres \
		-c "CREATE DATABASE computeid OWNER leadpilot;" 2>/dev/null \
		|| echo "db computeid already exists"
	@PGPASSWORD=leadpilot psql -h localhost -p 5439 -U leadpilot -d postgres \
		-c "CREATE DATABASE computeid_test OWNER leadpilot;" 2>/dev/null \
		|| echo "db computeid_test already exists"

.PHONY: db-reset
db-reset:
	PGPASSWORD=leadpilot psql -h localhost -p 5439 -U leadpilot -d postgres \
		-c "DROP DATABASE IF EXISTS computeid;"
	PGPASSWORD=leadpilot psql -h localhost -p 5439 -U leadpilot -d postgres \
		-c "CREATE DATABASE computeid OWNER leadpilot;"

# ---- run the server ----

.PHONY: run
run: db-up
	DATABASE_URL=$(DATABASE_URL) JWT_SECRET=$(JWT_SECRET) PORT=$(PORT) \
		$(GO) run ./cmd/computeid-server

# ---- examples ----

.PHONY: example-basic
example-basic:
	$(GO) run ./examples/basic

.PHONY: example-serverbacked
example-serverbacked:
	COMPUTEID_API_BASE=http://localhost:$(PORT) $(GO) run ./examples/serverbacked

.PHONY: example-devices
example-devices:
	COMPUTEID_API_BASE=http://localhost:$(PORT) COMPUTEID_AUTO_APPROVE=1 \
		$(GO) run ./examples/devices

# ---- docker bundle ----

.PHONY: docker-build
docker-build:
	docker build -t computeid-server:dev .

.PHONY: docker-up
docker-up:
	docker compose up --build

.PHONY: docker-down
docker-down:
	docker compose down -v

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'
