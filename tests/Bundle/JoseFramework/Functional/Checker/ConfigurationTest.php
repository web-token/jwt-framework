<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Checker;

use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Checker\CheckerSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Core\CoreSource;
use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class ConfigurationTest extends TestCase
{
    use ConfigurationTestCaseTrait;

    #[Test]
    public function theConfigurationIsValidIfNoConfigurationIsSet(): void
    {
        $this->assertConfigurationIsValid([]);
    }

    #[Test]
    public function theConfigurationIsValidIfConfigurationIsFalse(): void
    {
        $this->assertConfigurationIsValid([
            [
                'checkers' => false,
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsValidIfConfigurationIsEmpty(): void
    {
        $this->assertConfigurationIsValid([
            [
                'checkers' => [],
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsValidIfNoHeaderOrClaimCheckerIsSet(): void
    {
        $this->assertConfigurationIsValid([
            [
                'checkers' => [
                    'headers' => [],
                    'claims' => [],
                ],
            ],
        ]);
    }

    #[Test]
    public function theHeadersForAHeaderCheckerShouldBeSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'checkers' => [
                        'headers' => [
                            'foo' => [
                                'is_public' => false,
                            ],
                        ],
                    ],
                ],
            ],
            'he child config "headers" under "jose.checkers.headers.foo" must be configured:'
        );
    }

    #[Test]
    public function aHeaderCheckerMayContainNoChecker(): void
    {
        $this->assertConfigurationIsValid(
            [
                [
                    'checkers' => [
                        'headers' => [
                            'foo' => [
                                'headers' => [],
                                'is_public' => false,
                            ],
                        ],
                    ],
                ],
            ]
        );
    }

    #[Test]
    public function theClaimsForAClaimCheckerShouldBeSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'checkers' => [
                        'claims' => [
                            'foo' => [
                                'is_public' => false,
                            ],
                        ],
                    ],
                ],
            ],
            'he child config "claims" under "jose.checkers.claims.foo" must be configured:'
        );
    }

    #[Test]
    public function aClaimCheckerMayContainNoChecker(): void
    {
        $this->assertConfigurationIsValid(
            [
                [
                    'checkers' => [
                        'claims' => [
                            'foo' => [
                                'claims' => [],
                                'is_public' => false,
                            ],
                        ],
                    ],
                ],
            ]
        );
    }

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [new CoreSource(), new CheckerSource()]);
    }
}
