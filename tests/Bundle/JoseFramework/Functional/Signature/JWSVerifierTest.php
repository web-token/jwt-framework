<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

use Jose\Bundle\JoseFramework\Services\JWSVerifierFactory as JWSVerifierFactoryService;
use Jose\Component\Signature\JWSVerifier;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @internal
 */
final class JWSVerifierTest extends WebTestCase
{
    #[Test]
    public static function jWSVerifierFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has(JWSVerifierFactoryService::class));
    }

    #[Test]
    public static function jWSVerifierFactoryCanCreateAJWSVerifier(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        $jwsFactory = $container->get(JWSVerifierFactoryService::class);
        static::assertInstanceOf(JWSVerifierFactoryService::class, $jwsFactory);

        $jwsFactory->create(['none']);
    }

    #[Test]
    public static function jWSVerifierFromConfigurationIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_verifier.loader1'));

        $jws = $container->get('jose.jws_verifier.loader1');
        static::assertInstanceOf(JWSVerifier::class, $jws);
    }

    #[Test]
    public static function jWSVerifierFromExternalBundleExtensionIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_verifier.loader2'));

        $jws = $container->get('jose.jws_verifier.loader2');
        static::assertInstanceOf(JWSVerifier::class, $jws);
    }
}
