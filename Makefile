.PHONY: it
it: coding-standards tests static-analyse performance-tests mutation-tests

.PHONY: code-coverage
code-coverage: vendor ## Show test coverage rates
	vendor/bin/phpunit --coverage-text

.PHONY: fix-coding-standards
fix-coding-standards: vendor ## Fix all files using defined PHP-CS-FIXER rules
	vendor/bin/ecs --fix

.PHONY: coding-standards
coding-standards: vendor ## Check all files using defined PHP-CS-FIXER rules
	vendor/bin/ecs

.PHONY: mutation-tests
mutation-tests: vendor ## Run mutation tests with minimum MSI and covered MSI enabled
	vendor/bin/infection --logger-github -s --threads=$(nproc) --min-msi=80 --min-covered-msi=85

.PHONY: tests
tests: vendor ## Run all tests
	vendor/bin/phpunit  --color

vendor: composer.json composer.lock
	composer validate
	composer install
	composer normalize

.PHONY: tu
tu: vendor ## Run all unit tests
	vendor/bin/phpunit --color --group Unit

.PHONY: tf
tf: vendor ## Run all functional tests
	vendor/bin/phpunit --color --group Functional

.PHONY: static-analyse
static-analyse: vendor ## Run static analyse
	vendor/bin/phpstan analyse

.PHONY: performance-tests
performance-tests: vendor ## Run performance test suite
	vendor/bin/phpbench run -l dots --report aggregate

.PHONY: rector
rector: vendor ## Check all files using Rector
	vendor/bin/rector process --ansi --dry-run --xdebug


.DEFAULT_GOAL := help
help:
	@grep -E '(^[a-zA-Z_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'
.PHONY: help