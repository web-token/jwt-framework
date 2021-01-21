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

namespace Jose\Tests\Bundle\JoseFramework\Functional\Encryption;

use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source;
use Jose\Component\Encryption\JWEBuilderFactory;
use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use PHPUnit\Framework\TestCase;

/**
 * @group Bundle
 * @group Configuration
 *
 * @internal
 */
class SerializerConfigurationTest extends TestCase
{
    use ConfigurationTestCaseTrait;

    protected function setUp(): void
    {
        if (!class_exists(JWEBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-encryption" is not installed.');
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
                    'jwe' => false,
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
                    'jwe' => [],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValidIfNoSerializerIsSet(): void
    {
        $this->assertConfigurationIsValid(
            [
                [
                    'jwe' => [
                        'serializers' => [],
                    ],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoSerializerParameterIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwe' => [
                        'serializers' => [
                            'foo' => [],
                        ],
                    ],
                ],
            ],
            'The child config "serializers" under "jose.jwe.serializers.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfTheSerializerListIsEmpty(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwe' => [
                        'serializers' => [
                            'foo' => [
                                'serializers' => [],
                            ],
                        ],
                    ],
                ],
            ],
            'The path "jose.jwe.serializers.foo.serializers" should have at least 1 element(s) defined.'
        );
    }

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [
            new Source\Core\CoreSource(),
            new Source\Encryption\EncryptionSource(),
        ]);
    }
}
