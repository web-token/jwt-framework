<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Checker;

use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory as ClaimCheckerManagerFactoryService;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @internal
 */
final class ClaimCheckerTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (! class_exists(ClaimCheckerManagerFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-checker" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theClaimCheckerManagerFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has(ClaimCheckerManagerFactoryService::class));
    }

    /**
     * @test
     */
    public function theClaimCheckerManagerFactoryCanCreateAClaimCheckerManager(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $claimCheckerManagerFactory = $container->get(ClaimCheckerManagerFactoryService::class);
        static::assertInstanceOf(ClaimCheckerManagerFactoryService::class, $claimCheckerManagerFactory);

        $aliases = $claimCheckerManagerFactory->aliases();
        $claimCheckerManagerFactory->create($aliases);
    }

    /**
     * @test
     */
    public function aClaimCheckerCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.claim_checker.checker1'));
    }

    /**
     * @test
     */
    public function aClaimCheckerCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.claim_checker.checker2'));
    }
}
