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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Encryption;

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
 * @coversNothing
 */
class JweBuilderConfigurationTest extends TestCase
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
                    'jwe' => false,
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
                    'jwe' => [],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfBuilderIsSet()
    {
        $this->assertConfigurationIsValid(
            [
                [
                    'jwe' => [
                        'builders' => [],
                    ],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNotKeyEncryptionAlgorithmIsSet()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwe' => [
                        'builders' => [
                            'foo' => [],
                        ],
                    ],
                ],
            ],
            'The child node "key_encryption_algorithms" at path "jose.jwe.builders.foo" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfTheKeyEncryptionAlgorithmIsEmpty()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwe' => [
                        'builders' => [
                            'foo' => [
                                'key_encryption_algorithms' => [],
                            ],
                        ],
                    ],
                ],
            ],
            'The path "jose.jwe.builders.foo.key_encryption_algorithms" should have at least 1 element(s) defined.'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNotContentEncryptionAlgorithmIsSet()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwe' => [
                        'builders' => [
                            'foo' => [
                                'key_encryption_algorithms' => ['A256GCMKW'],
                            ],
                        ],
                    ],
                ],
            ],
            'The child node "content_encryption_algorithms" at path "jose.jwe.builders.foo" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfTheContentEncryptionAlgorithmIsEmpty()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwe' => [
                        'builders' => [
                            'foo' => [
                                'key_encryption_algorithms' => ['A256GCMKW'],
                                'content_encryption_algorithms' => [],
                            ],
                        ],
                    ],
                ],
            ],
            'The path "jose.jwe.builders.foo.content_encryption_algorithms" should have at least 1 element(s) defined.'
        );
    }

    protected function getConfiguration()
    {
        return new Configuration('jose', [
            new Source\Core\CoreSource(),
            new Source\Encryption\EncryptionSource(),
        ]);
    }
}
