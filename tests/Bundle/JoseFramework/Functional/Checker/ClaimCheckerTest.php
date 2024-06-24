<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Checker;

use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory as ClaimCheckerManagerFactoryService;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

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

        $aliases = $claimCheckerManagerFactory->aliases();
        $claimCheckerManagerFactory->create($aliases);
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
}
