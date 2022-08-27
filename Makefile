include .env
export

#
# Helpers
#

## help: print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

.PHONY: confirm
confirm:
	@echo -n 'Are you sure? [y/N] ' && read ans && [ $${ans:-N} = y ]

#
# Development
#

## examples/server/run: run the example server
.PHONY: examples/server/run
examples/server/run:
	@go run ./examples/server/*.go

## migrations/new name=$1: create a new database migration file
.PHONY: migrations/new
migrations/new:
	@echo 'Creating a new migration for ${name}...'
	migrate create -seq -digits 3 -ext=.sql -dir=./migrations ${name}

## migrations/up: apply all up database migrations
.PHONY: migrations/up
migrations/up: confirm
	@echo 'Running up migrations...'
	migrate -path ./migrations -database '${MIGRATE_DB_DSN}' up

## migrations/down: apply all down database migrations
.PHONY: migrations/down
migrations/down:
	@echo 'Running down migrations...'
	migrate -path ./migrations -database '${MIGRATE_DB_DSN}' down