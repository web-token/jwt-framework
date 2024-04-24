<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Encryption;

use Jose\Component\Encryption\Serializer\JWESerializerManager;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @internal
 */
final class JWESerializerTest extends WebTestCase
{
    #[Test]
    public static function jWESerializerManagerFromConfigurationIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_serializer.jwe_serializer1'));

        $jwe = $container->get('jose.jwe_serializer.jwe_serializer1');
        static::assertInstanceOf(JWESerializerManager::class, $jwe);
    }

    #[Test]
    public static function jWESerializerManagerFromExternalBundleExtensionIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_serializer.jwe_serializer2'));

        $jwe = $container->get('jose.jwe_serializer.jwe_serializer2');
        static::assertInstanceOf(JWESerializerManager::class, $jwe);
    }
}
