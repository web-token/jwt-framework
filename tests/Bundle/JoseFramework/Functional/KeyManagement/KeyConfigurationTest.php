<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Core\CoreSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\KeyManagementSource;
use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class KeyConfigurationTest extends TestCase
{
    use ConfigurationTestCaseTrait;

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
                'keys' => false,
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsValidIfConfigurationIsEmpty(): void
    {
        $this->assertConfigurationIsValid([
            [
                'keys' => [],
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsInvalidIfNoKeyTypeIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'keys' => [
                        'foo' => [],
                    ],
                ],
            ],
            'Invalid configuration for path "jose.keys.foo": One key type must be set.'
        );
    }

    #[Test]
    public function theConfigurationIsInvalidIfAnUnsupportedKeyTypeIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'keys' => [
                        'foo' => [
                            'bad' => [],
                        ],
                    ],
                ],
            ],
            'Unrecognized option "bad" under "jose.keys.foo"'
        );
    }

    #[Test]
    public function theCertificateConfigurationIsInvalidIfRequiredParametersAreNotSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'keys' => [
                        'foo' => [
                            'certificate' => [],
                        ],
                    ],
                ],
            ],
            'The child config "path" under "jose.keys.foo.certificate" must be configured:'
        );
    }

    #[Test]
    public function theJwkConfigurationIsInvalidIfRequiredParametersAreNotSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'keys' => [
                        'foo' => [
                            'jwk' => [],
                        ],
                    ],
                ],
            ],
            'The child config "value" under "jose.keys.foo.jwk" must be configured:'
        );
    }

    #[Test]
    public function theJwkSetConfigurationIsInvalidIfRequiredParametersAreNotSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'keys' => [
                        'foo' => [
                            'jwkset' => [],
                        ],
                    ],
                ],
            ],
            'The child config "key_set" under "jose.keys.foo.jwkset" must be configured:'
        );
    }

    #[Test]
    public function theJwkSetConfigurationIsInvalidIfRequiredParametersAreNotSet2(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'keys' => [
                        'foo' => [
                            'jwkset' => [
                                'key_set' => 'foo',
                            ],
                        ],
                    ],
                ],
            ],
            'The child config "index" under "jose.keys.foo.jwkset" must be configured:'
        );
    }

    #[Test]
    public function theKeyFileConfigurationIsInvalidIfRequiredParametersAreNotSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'keys' => [
                        'foo' => [
                            'file' => [],
                        ],
                    ],
                ],
            ],
            'The child config "path" under "jose.keys.foo.file" must be configured:'
        );
    }

    #[Test]
    public function theValuesConfigurationIsInvalidIfRequiredParametersAreNotSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'keys' => [
                        'foo' => [
                            'values' => [],
                        ],
                    ],
                ],
            ],
            'The child config "values" under "jose.keys.foo.values" must be configured:'
        );
    }

    #[Test]
    public function theX5CConfigurationIsInvalidIfRequiredParametersAreNotSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'keys' => [
                        'foo' => [
                            'x5c' => [],
                        ],
                    ],
                ],
            ],
            'The child config "value" under "jose.keys.foo.x5c" must be configured:'
        );
    }

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [new CoreSource(), new KeyManagementSource()]);
    }
}
