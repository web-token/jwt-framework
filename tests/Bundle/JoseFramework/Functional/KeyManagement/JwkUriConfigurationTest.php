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
class JwkUriConfigurationTest extends TestCase
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
                    'jwk_uris' => false,
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
                    'jwk_uris' => [],
                ],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoKeySetIdIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwk_uris' => [
                        'foo' => [],
                    ],
                ],
            ],
            'The child config "id" under "jose.jwk_uris.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsInvalidIfNoPathIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwk_uris' => [
                        'foo' => [
                            'id' => 'foo',
                        ],
                    ],
                ],
            ],
            'The child config "path" under "jose.jwk_uris.foo" must be configured:'
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
