<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework;

use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;

/**
 * Keeps the upstream configuration assertions and replaces only the invalid-configuration one.
 *
 * `ConfigurationValuesAreInvalidConstraint` hands the caught exception to PHPUnit's
 * `ExceptionMessageIsOrContains`, which since PHPUnit 10.0.15 matches against the message string instead of
 * the exception object. Every expectation therefore fails with an empty message, whatever the configuration
 * actually reported. matthiasnoback/symfony-config-test v6.2.0 is the latest release and still does this.
 */
trait ConfigurationAssertionsTrait
{
    use ConfigurationTestCaseTrait;

    /**
     * @param array<array-key, mixed> $configurationValues
     */
    protected function assertConfigurationIsInvalid(
        array $configurationValues,
        $expectedMessage = null,
        $useRegExp = false
    ): void {
        try {
            (new Processor())->processConfiguration($this->getConfiguration(), $configurationValues);
        } catch (InvalidConfigurationException $exception) {
            if ($expectedMessage === null) {
                static::assertTrue(true);

                return;
            }
            if ($useRegExp === true) {
                static::assertMatchesRegularExpression($expectedMessage, $exception->getMessage());

                return;
            }
            static::assertStringContainsString($expectedMessage, $exception->getMessage());

            return;
        }

        static::fail('The configuration should have been considered invalid.');
    }
}
