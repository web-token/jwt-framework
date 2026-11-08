<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Checker;

use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory as ClaimCheckerManagerFactoryService;
use Jose\Component\Checker\CallableChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;

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
    public function anAliasCoveringAClaimAlreadyCheckedIsRejected(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The claim "exp" is given two checkers, "%s" and "%s", but a claim checker manager takes a single checker per claim. Combine the rules of a claim in a single checker.',
            ExpirationTimeChecker::class,
            CallableChecker::class
        ));

        $container->get('jose.claim_checker.exp_twice');
    }
}
