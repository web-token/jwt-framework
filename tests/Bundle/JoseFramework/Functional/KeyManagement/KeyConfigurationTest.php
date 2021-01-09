<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source;
use Jose\Component\KeyManagement\JWKFactory;
use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use PHPUnit\Framework\TestCase;

/**
 * @group Bundle
 * @group Configuration
 *
 * @internal
 */
class KeyConfigurationTest extends TestCase
{
    use ConfigurationTestCaseTrait;

    protected function setUp(): void
    {
        if (!class_exists(JWKFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-key-mgmt" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theConfigurationIsValidIfNoConfigurationIsSet(): void
    {
        $this->assertConfigurationIsValid(
            []
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValidIfConfigurationIsFalse(): void
    {
        $this->assertConfigurationIsValid(
            [
                [
                    'keys' => false,
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValidIfConfigurationIsEmpty(): void
    {
        $this->assertConfigurationIsValid(
            [
                [
                    'keys' => [],
                ],
            ]
        );
    }

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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
        return new Configuration('jose', [
            new Source\Core\CoreSource(),
            new Source\KeyManagement\KeyManagementSource(),
        ]);
    }
}
