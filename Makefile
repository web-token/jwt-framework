code-coverage: vendor ## Show test coverage rates
	vendor/bin/phpunit --coverage-text

fix-coding-standards: vendor ## Fix all files using defined PHP-CS-FIXER rules
	vendor/bin/ecs --fix

coding-standards: vendor ## Check all files using defined PHP-CS-FIXER rules
	vendor/bin/ecs

mutation-tests: vendor ## Run mutation tests with minimum MSI and covered MSI enabled
	vendor/bin/infection --logger-github -s --threads=$(nproc) --min-msi=80 --min-covered-msi=85

tests: vendor ## Run all tests
	vendor/bin/phpunit  --color

vendor: composer.json composer.lock
	composer validate
	composer install
	composer normalize

tu: vendor ## Run all unit tests
	vendor/bin/phpunit --color --group Unit

tf: vendor ## Run all functional tests
	vendor/bin/phpunit --color --group Functional

static-analyse: vendor ## Run static analyse
	vendor/bin/phpstan analyse

performance-tests: vendor ## Run performance test suite
	vendor/bin/phpbench run -l dots --report aggregate

rector: vendor ## Check all files using Rector
	vendor/bin/rector process --ansi --dry-run --xdebug


.DEFAULT_GOAL := help
help:
	@grep -E '(^[a-zA-Z_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'
.PHONY: help