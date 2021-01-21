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

namespace Jose\Tests\Bundle\JoseFramework\Functional\Checker;

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
                ['checkers' => false],
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
                ['checkers' => []],
            ]
        );
    }

    /**
     * @test
     */
    public function theConfigurationIsValidIfNoHeaderOrClaimCheckerIsSet(): void
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
    public function theHeadersForAHeaderCheckerShouldBeSet(): void
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
            'he child config "headers" under "jose.checkers.headers.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function aHeaderCheckerMayContainNoChecker(): void
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
    public function theClaimsForAClaimCheckerShouldBeSet(): void
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
            'he child config "claims" under "jose.checkers.claims.foo" must be configured:'
        );
    }

    /**
     * @test
     */
    public function aClaimCheckerMayContainNoChecker(): void
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

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [
            new Source\Core\CoreSource(),
            new Source\Checker\CheckerSource(),
        ]);
    }
}
