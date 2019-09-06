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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Signature;

use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source;
use Jose\Component\Signature\JWSBuilderFactory;
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
        if (!class_exists(JWSBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-signature" is not installed.');
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
                    'jws' => false,
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
                    'jws' => [],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValidIfNoSerializerIsSet()
    {
        $this->assertConfigurationIsValid(
            [
                [
                    'jws' => [
                        'serializers' => [],
                    ],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoSerializerParameterIsSet()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jws' => [
                        'serializers' => [
                            'foo' => [],
                        ],
                    ],
                ],
            ],
            'The child node "serializers" at path "jose.jws.serializers.foo" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfTheSerializerListIsEmpty()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jws' => [
                        'serializers' => [
                            'foo' => [
                                'serializers' => [],
                            ],
                        ],
                    ],
                ],
            ],
            'The path "jose.jws.serializers.foo.serializers" should have at least 1 element(s) defined.'
        );
    }

    protected function getConfiguration()
    {
        return new Configuration('jose', [
            new Source\Core\CoreSource(),
            new Source\Signature\SignatureSource(),
        ]);
    }
}
