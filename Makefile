.PHONY: lint
lint:
	@devenv tasks run devenv:git-hooks:run

.PHONY: format
format:
	@devenv tasks run devenv:treefmt:run

.PHONY: test
test:
	go test -v -race  -covermode=atomic ./...

caddy: build/darwin/caddy
build/darwin/caddy:
	test -f $(@D) || mkdir -p $(@D)
	CGO_ENABLED=1 xcaddy build \
		--output $(@) \
		--with github.com/hurricanehrndz/caddy-certstore=.

.PHONY: install-hooks
install-hooks:
	@devenv tasks run devenv:git-hooks:install
