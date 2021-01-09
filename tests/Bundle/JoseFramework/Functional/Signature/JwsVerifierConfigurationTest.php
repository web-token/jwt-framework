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

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

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
class JwsVerifierConfigurationTest extends TestCase
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
                    'jws' => false,
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
                    'jws' => [],
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
                    'jws' => [
                        'verifiers' => [],
                    ],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNotSignatureAlgorithmIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jws' => [
                        'verifiers' => [
                            'foo' => [],
                        ],
                    ],
                ],
            ],
            'The child config "signature_algorithms" under "jose.jws.verifiers.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfTheSignatureAlgorithmIsEmpty(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jws' => [
                        'verifiers' => [
                            'foo' => [
                                'signature_algorithms' => [],
                            ],
                        ],
                    ],
                ],
            ],
            'The path "jose.jws.verifiers.foo.signature_algorithms" should have at least 1 element(s) defined.'
        );
    }

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [
            new Source\Core\CoreSource(),
            new Source\Signature\SignatureSource(),
        ]);
    }
}
