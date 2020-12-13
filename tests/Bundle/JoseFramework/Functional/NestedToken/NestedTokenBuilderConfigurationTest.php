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

namespace Jose\Tests\Bundle\JoseFramework\Functional\NestedToken;

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
                    'nested_token' => false,
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
                    'nested_token' => [],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValidIfNoBuilderIsSet(): void
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
    public function theConfigurationIsInvalidIfNoSignatureAlgorithmIsSet(): void
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
            'The child config "signature_algorithms" under "jose.nested_token.builders.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoKeyEncryptionAlgorithmIsSet(): void
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
            'The child config "key_encryption_algorithms" under "jose.nested_token.builders.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoContentEncryptionAlgorithmIsSet(): void
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
            'The child config "content_encryption_algorithms" under "jose.nested_token.builders.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoJwsSerializerIsSet(): void
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
            'The child config "jws_serializers" under "jose.nested_token.builders.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoJweSerializerIsSet(): void
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
            'The child config "jwe_serializers" under "jose.nested_token.builders.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValid(): void
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

    protected function getConfiguration(): Configuration
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
