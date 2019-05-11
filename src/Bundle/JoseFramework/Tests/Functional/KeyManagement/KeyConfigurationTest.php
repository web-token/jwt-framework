<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Tests\Functional\KeyManagement;

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
 * @coversNothing
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
    public function theConfigurationIsValidIfNoConfigurationIsSet()
    {
        $this->assertConfigurationIsValid(
            []
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValidIfConfigurationIsFalse()
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
    public function theConfigurationIsValidIfConfigurationIsEmpty()
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
    public function theConfigurationIsInvalidIfNoKeyTypeIsSet()
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
    public function theConfigurationIsInvalidIfAnUnsupportedKeyTypeIsSet()
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
    public function theCertificateConfigurationIsInvalidIfRequiredParametersAreNotSet()
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
            'The child node "path" at path "jose.keys.foo.certificate" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theJwkConfigurationIsInvalidIfRequiredParametersAreNotSet()
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
            'The child node "value" at path "jose.keys.foo.jwk" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theJwkSetConfigurationIsInvalidIfRequiredParametersAreNotSet()
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
            'The child node "key_set" at path "jose.keys.foo.jwkset" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theJwkSetConfigurationIsInvalidIfRequiredParametersAreNotSet2()
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
            'The child node "index" at path "jose.keys.foo.jwkset" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theKeyFileConfigurationIsInvalidIfRequiredParametersAreNotSet()
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
            'The child node "path" at path "jose.keys.foo.file" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theValuesConfigurationIsInvalidIfRequiredParametersAreNotSet()
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
            'The child node "values" at path "jose.keys.foo.values" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theX5CConfigurationIsInvalidIfRequiredParametersAreNotSet()
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
            'The child node "value" at path "jose.keys.foo.x5c" must be configured.'
        );
    }

    protected function getConfiguration()
    {
        return new Configuration('jose', [
            new Source\Core\CoreSource(),
            new Source\KeyManagement\KeyManagementSource(),
        ]);
    }
}
