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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Checker;

use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use PHPUnit\Framework\TestCase;

/**
 * @group Bundle
 * @group Configuration
 *
 * @internal
 * @coversNothing
 */
class ConfigurationTest extends TestCase
{
    use ConfigurationTestCaseTrait;

    protected function setUp(): void
    {
        if (!class_exists(ClaimCheckerManagerFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-checker" is not installed.');
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
                ['checkers' => false],
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
                ['checkers' => []],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValidIfNoHeaderOrClaimCheckerIsSet()
    {
        $this->assertConfigurationIsValid(
            [
                ['checkers' => [
                    'headers' => [],
                    'claims' => [],
                ]],
            ]
        );
    }

    /**
     * @test
     */
    public function theHeadersForAHeaderCheckerShouldBeSet()
    {
        $this->assertConfigurationIsInvalid(
            [
                ['checkers' => [
                    'headers' => [
                        'foo' => [
                            'is_public' => false,
                        ],
                    ],
                ]],
            ],
            'he child node "headers" at path "jose.checkers.headers.foo" must be configured.'
        );
    }

    /**
     * @test
     */
    public function aHeaderCheckerMayContainNoChecker()
    {
        $this->assertConfigurationIsValid(
            [
                ['checkers' => [
                    'headers' => [
                        'foo' => [
                            'headers' => [],
                            'is_public' => false,
                        ],
                    ],
                ]],
            ]
        );
    }

    /**
     * @test
     */
    public function theClaimsForAClaimCheckerShouldBeSet()
    {
        $this->assertConfigurationIsInvalid(
            [
                ['checkers' => [
                    'claims' => [
                        'foo' => [
                            'is_public' => false,
                        ],
                    ],
                ]],
            ],
            'he child node "claims" at path "jose.checkers.claims.foo" must be configured.'
        );
    }

    /**
     * @test
     */
    public function aClaimCheckerMayContainNoChecker()
    {
        $this->assertConfigurationIsValid(
            [
                ['checkers' => [
                    'claims' => [
                        'foo' => [
                            'claims' => [],
                            'is_public' => false,
                        ],
                    ],
                ]],
            ]
        );
    }

    protected function getConfiguration()
    {
        return new Configuration('jose', [
            new Source\Core\CoreSource(),
            new Source\Checker\CheckerSource(),
        ]);
    }
}
