<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

use Jose\Component\Signature\Serializer\JWSSerializerManager;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @internal
 */
final class JWSSerializerTest extends WebTestCase
{
    #[Test]
    public static function jWSSerializerManagerFromConfigurationIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_serializer.jws_serializer1'));

        $jws = $container->get('jose.jws_serializer.jws_serializer1');
        static::assertInstanceOf(JWSSerializerManager::class, $jws);
    }

    #[Test]
    public static function jWSSerializerManagerFromExternalBundleExtensionIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_serializer.jws_serializer2'));

        $jws = $container->get('jose.jws_serializer.jws_serializer2');
        static::assertInstanceOf(JWSSerializerManager::class, $jws);
    }
}
