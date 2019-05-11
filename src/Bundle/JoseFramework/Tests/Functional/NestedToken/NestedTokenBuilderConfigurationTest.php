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

namespace Jose\Bundle\JoseFramework\Tests\Functional\NestedToken;

use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source;
use Jose\Bundle\JoseFramework\Services\NestedTokenLoaderFactory;
use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use PHPUnit\Framework\TestCase;

/**
 * @group Bundle
 * @group functional
 * @group NestedToken
 *
 * @internal
 * @coversNothing
 */
class NestedTokenBuilderConfigurationTest extends TestCase
{
    use ConfigurationTestCaseTrait;

    protected function setUp(): void
    {
        if (!class_exists(NestedTokenLoaderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-nested-token" is not installed.');
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
                    'nested_token' => false,
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
                    'nested_token' => [],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValidIfNoBuilderIsSet()
    {
        $this->assertConfigurationIsValid(
            [
                [
                    'nested_token' => [
                        'builders' => [],
                    ],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoSignatureAlgorithmIsSet()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'nested_token' => [
                        'builders' => [
                            'foo' => [],
                        ],
                    ],
                ],
            ],
            'The child node "signature_algorithms" at path "jose.nested_token.builders.foo" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoKeyEncryptionAlgorithmIsSet()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'nested_token' => [
                        'builders' => [
                            'foo' => [
                                'signature_algorithms' => ['RS256'],
                            ],
                        ],
                    ],
                ],
            ],
            'The child node "key_encryption_algorithms" at path "jose.nested_token.builders.foo" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoContentEncryptionAlgorithmIsSet()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'nested_token' => [
                        'builders' => [
                            'foo' => [
                                'signature_algorithms' => ['RS256'],
                                'key_encryption_algorithms' => ['RSA-OAEP'],
                            ],
                        ],
                    ],
                ],
            ],
            'The child node "content_encryption_algorithms" at path "jose.nested_token.builders.foo" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoJwsSerializerIsSet()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'nested_token' => [
                        'builders' => [
                            'foo' => [
                                'signature_algorithms' => ['RS256'],
                                'key_encryption_algorithms' => ['RSA-OAEP'],
                                'content_encryption_algorithms' => ['A128GCM'],
                            ],
                        ],
                    ],
                ],
            ],
            'The child node "jws_serializers" at path "jose.nested_token.builders.foo" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoJweSerializerIsSet()
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'nested_token' => [
                        'builders' => [
                            'foo' => [
                                'signature_algorithms' => ['RS256'],
                                'key_encryption_algorithms' => ['RSA-OAEP'],
                                'content_encryption_algorithms' => ['A128GCM'],
                                'jws_serializers' => ['jws_compact'],
                            ],
                        ],
                    ],
                ],
            ],
            'The child node "jwe_serializers" at path "jose.nested_token.builders.foo" must be configured.'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValid()
    {
        $this->assertConfigurationIsValid(
            [
                [
                    'nested_token' => [
                        'builders' => [
                            'foo' => [
                                'signature_algorithms' => ['RS256'],
                                'key_encryption_algorithms' => ['RSA-OAEP'],
                                'content_encryption_algorithms' => ['A128GCM'],
                                'jws_serializers' => ['jws_compact'],
                                'jwe_serializers' => ['jwe_compact'],
                            ],
                        ],
                    ],
                ],
            ]
        );
    }

    protected function getConfiguration()
    {
        return new Configuration('jose', [
            new Source\Core\CoreSource(),
            new Source\Checker\CheckerSource(),
            new Source\Signature\SignatureSource(),
            new Source\Encryption\EncryptionSource(),
            new Source\NestedToken\NestedToken(),
        ]);
    }
}
