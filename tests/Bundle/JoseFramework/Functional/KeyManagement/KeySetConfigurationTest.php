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
class KeySetConfigurationTest extends TestCase
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
                    'key_sets' => false,
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
                    'key_sets' => [],
                ],
            ]
        );
    }

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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
        return new Configuration('jose', [
            new Source\Core\CoreSource(),
            new Source\KeyManagement\KeyManagementSource(),
        ]);
    }
}
