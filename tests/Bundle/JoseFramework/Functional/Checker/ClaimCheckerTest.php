<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Checker;

use Jose\Bundle\JoseFramework\Services\ClaimCheckerManager;
use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory as ClaimCheckerManagerFactoryService;
use Jose\Component\Checker\CallableChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use const E_USER_DEPRECATED;

/**
 * @internal
 */
final class ClaimCheckerTest extends WebTestCase
{
    #[Test]
    public static function theClaimCheckerManagerFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has(ClaimCheckerManagerFactoryService::class));
    }

    #[Test]
    public static function theClaimCheckerManagerFactoryCanCreateAClaimCheckerManager(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        $claimCheckerManagerFactory = $container->get(ClaimCheckerManagerFactoryService::class);
        static::assertInstanceOf(ClaimCheckerManagerFactoryService::class, $claimCheckerManagerFactory);

        $aliases = array_diff($claimCheckerManagerFactory->aliases(), ['max_lifetime']);
        $claimCheckerManagerFactory->create(array_values($aliases));
    }

    #[Test]
    public static function aClaimCheckerCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.claim_checker.checker1'));
    }

    #[Test]
    public static function aClaimCheckerCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.claim_checker.checker2'));
    }

    #[Test]
    public function anAliasCoveringAClaimAlreadyCheckedIsDeprecated(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        $deprecations = self::collectDeprecations(static function () use ($container): void {
            $claimCheckerManager = $container->get('jose.claim_checker.exp_twice');

            static::assertInstanceOf(ClaimCheckerManager::class, $claimCheckerManager);
            static::assertInstanceOf(CallableChecker::class, $claimCheckerManager->getCheckers()['exp'] ?? null);
        });

        static::assertSame([
            sprintf(
                'Since web-token/jwt-library 4.3.0: Building a claim checker manager with more than one checker of the claim "exp" is deprecated and will not be possible in 5.0.0: only the last one is kept, so "%s" replaces "%s", which never runs. Combine the rules of a claim in a single checker.',
                CallableChecker::class,
                ExpirationTimeChecker::class
            ),
        ], $deprecations);
    }

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private static function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
