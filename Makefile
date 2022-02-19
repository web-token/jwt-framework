mu: vendor ## Mutation tests
	vendor/bin/infection -s --threads=$(nproc) --min-msi=40 --min-covered-msi=40

tests: vendor ## Run all tests
	vendor/bin/phpunit  --color

cc: vendor ## Show test coverage rates (HTML)
	vendor/bin/phpunit --coverage-html ./build

cs: vendor ## Fix all files using defined ECS rules
	vendor/bin/ecs check --fix

tu: vendor ## Run only unit tests
	vendor/bin/phpunit --color --group Unit

ti: vendor ## Run only integration tests
	vendor/bin/phpunit --color --group Integration

tf: vendor ## Run only functional tests
	vendor/bin/phpunit --color --group Functional

st: vendor ## Run static analyse
	vendor/bin/phpstan analyse


################################################

ci-mu: vendor ## Mutation tests (for Github only)
	vendor/bin/infection --logger-github -s --threads=$(nproc) --min-msi=40 --min-covered-msi=40

ci-cc: vendor ## Show test coverage rates (console)
	vendor/bin/phpunit --coverage-text

ci-cs: vendor ## Check all files using defined ECS rules
	vendor/bin/ecs check

################################################


vendor: composer.json composer.lock
	composer validate
	composer install

rector: vendor ## Check all files using Rector
	vendor/bin/rector process --ansi --dry-run --xdebug

.DEFAULT_GOAL := help
help:
	@grep -E '(^[a-zA-Z_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'
.PHONY: help
