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
class JweDecrypterConfigurationTest extends TestCase
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
    public function theConfigurationIsInvalidIfBuilderIsSet(): void
    {
        $this->assertConfigurationIsValid(
            [
                [
                    'jwe' => [
                        'decrypters' => [],
                    ],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNotKeyEncryptionAlgorithmIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwe' => [
                        'decrypters' => [
                            'foo' => [],
                        ],
                    ],
                ],
            ],
            'The child config "key_encryption_algorithms" under "jose.jwe.decrypters.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfTheKeyEncryptionAlgorithmIsEmpty(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwe' => [
                        'decrypters' => [
                            'foo' => [
                                'key_encryption_algorithms' => [],
                            ],
                        ],
                    ],
                ],
            ],
            'The path "jose.jwe.decrypters.foo.key_encryption_algorithms" should have at least 1 element(s) defined.'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNotContentEncryptionAlgorithmIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwe' => [
                        'decrypters' => [
                            'foo' => [
                                'key_encryption_algorithms' => ['A256GCMKW'],
                            ],
                        ],
                    ],
                ],
            ],
            'The child config "content_encryption_algorithms" under "jose.jwe.decrypters.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfTheContentEncryptionAlgorithmIsEmpty(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwe' => [
                        'decrypters' => [
                            'foo' => [
                                'key_encryption_algorithms' => ['A256GCMKW'],
                                'content_encryption_algorithms' => [],
                            ],
                        ],
                    ],
                ],
            ],
            'The path "jose.jwe.decrypters.foo.content_encryption_algorithms" should have at least 1 element(s) defined.'
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
