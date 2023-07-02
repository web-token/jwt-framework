<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use PHPUnit\Framework\Attributes\Test;
use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Core\CoreSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\KeyManagementSource;
use Jose\Component\KeyManagement\JWKFactory;
use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class KeySetConfigurationTest extends TestCase
{
    use ConfigurationTestCaseTrait;

    protected function setUp(): void
    {
        if (! class_exists(JWKFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-key-mgmt" is not installed.');
        }
    }

    #[Test]
    public function theConfigurationIsValidIfNoConfigurationIsSet(): void
    {
        $this->assertConfigurationIsValid([]);
    }

    #[Test]
    public function theConfigurationIsValidIfConfigurationIsFalse(): void
    {
        $this->assertConfigurationIsValid([
            [
                'key_sets' => false,
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsValidIfConfigurationIsEmpty(): void
    {
        $this->assertConfigurationIsValid([
            [
                'key_sets' => [],
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsInvalidIfNoKeySetTypeIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'key_sets' => [
                        'foo' => [],
                    ],
                ],
            ],
            'Invalid configuration for path "jose.key_sets.foo": One key set type must be set.'
        );
    }

    #[Test]
    public function theConfigurationIsInvalidIfAnUnsupportedKeySetTypeIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'key_sets' => [
                        'foo' => [
                            'bad' => [],
                        ],
                    ],
                ],
            ],
            'Unrecognized option "bad" under "jose.key_sets.foo"'
        );
    }

    #[Test]
    public function theJkuConfigurationIsInvalidIfRequiredParametersAreNotSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'key_sets' => [
                        'foo' => [
                            'jku' => [],
                        ],
                    ],
                ],
            ],
            'The child config "url" under "jose.key_sets.foo.jku" must be configured:'
        );
    }

    #[Test]
    public function theJwkSetConfigurationIsInvalidIfRequiredParametersAreNotSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'key_sets' => [
                        'foo' => [
                            'jwkset' => [],
                        ],
                    ],
                ],
            ],
            'The child config "value" under "jose.key_sets.foo.jwkset" must be configured:'
        );
    }

    #[Test]
    public function theX5UConfigurationIsInvalidIfRequiredParametersAreNotSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'key_sets' => [
                        'foo' => [
                            'x5u' => [],
                        ],
                    ],
                ],
            ],
            'The child config "url" under "jose.key_sets.foo.x5u" must be configured:'
        );
    }

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [new CoreSource(), new KeyManagementSource()]);
    }
}
