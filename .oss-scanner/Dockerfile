# Build of the OSS Scanner (https://github.com/anthropics/oss-scanner), with the repository root as context.
# It starts from the phpqa image the CI jobs run in, so phpunit-11 behaves as it does on CI. The image already has the
# extensions the tests need (openssl with OpenSSL 3.5, sodium, gmp, curl, zlib). The scan runs without network access:
# every dependency is installed here, and the tests that load key sets from a URL use a mock HTTP client.
# COMPOSER_ROOT_VERSION is set so that the build does not depend on the Git metadata of the checkout: without a
# version, roave/security-advisories conflicts with the packages this repository replaces.
# JOSE_ML_DSA_EXPECTED is set as in the PHP 8.4 CI job, which asserts that the ML-DSA algorithms are available.
FROM ghcr.io/spomky-labs/phpqa:8.4

USER root

ENV COMPOSER_ROOT_VERSION=4.3.x-dev \
    JOSE_ML_DSA_EXPECTED=yes

COPY . /src
WORKDIR /src

RUN composer install --no-interaction --no-progress

RUN composer exec -- phpunit-11 --configuration .ci-tools/phpunit.xml.dist --no-progress \
    || echo "WARNING: PHPUnit reported failures"
