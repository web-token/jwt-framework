<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Encryption;

use Jose\Bundle\JoseFramework\Services\JWELoaderFactory as JWELoaderFactoryAlias;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
final class JWELoaderTest extends WebTestCase
{
    #[Test]
    public static function theJWELoaderFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has(JWELoaderFactoryAlias::class));
    }

    #[Test]
    public static function theWELoaderFactoryCanCreateAJWELoader(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        $jweLoaderFactory = $container->get(JWELoaderFactoryAlias::class);
        static::assertInstanceOf(JWELoaderFactoryAlias::class, $jweLoaderFactory);

        $jwe = $jweLoaderFactory->create(['jwe_compact'], ['RSA1_5', 'A256GCM']);

        static::assertSame(['jwe_compact'], $jwe->getSerializerManager()->names());
        static::assertSame(['RSA1_5'], $jwe->getJweDecrypter()->getKeyEncryptionAlgorithmManager()->list());
        static::assertSame(['A256GCM'], $jwe->getJweDecrypter()->getContentEncryptionAlgorithmManager()->list());
    }

    #[Test]
    public static function aJWELoaderCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_loader.jwe_loader1'));

        $jwe = $container->get('jose.jwe_loader.jwe_loader1');
        static::assertInstanceOf(JWELoader::class, $jwe);
    }

    #[Test]
    public static function aJWELoaderCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_loader.jwe_loader2'));

        $jwe = $container->get('jose.jwe_loader.jwe_loader2');
        static::assertInstanceOf(JWELoader::class, $jwe);
    }

    #[Test]
    public static function theMaximumNumberOfRecipientsCanBeSetInTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        $jweLoader = $container->get('jose.jwe_loader.jwe_loader_limited');
        static::assertInstanceOf(JWELoader::class, $jweLoader);
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);
        $otherKey = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);
        $jweBuilder = (new JWEBuilder(new AlgorithmManager([new A256KW(), new A256GCM()])))
            ->withPayload('Live long and prosper.')
            ->withSharedProtectedHeader([
                'alg' => 'A256KW',
                'enc' => 'A256GCM',
            ]);
        $serializer = new JSONGeneralSerializer();
        $oneRecipient = $serializer->serialize($jweBuilder->addRecipient($key)->build());
        $twoRecipients = $serializer->serialize($jweBuilder->addRecipient($otherKey)->addRecipient($key)->build());

        static::assertSame(
            'Live long and prosper.',
            $jweLoader->loadAndDecrypt($oneRecipient, $key)
                ->getJwe()
                ->getPayload()
        );
        try {
            $jweLoader->loadAndDecrypt($twoRecipients, $key);
        } catch (InvalidTokenException $exception) {
            static::assertSame(
                'The token has too many recipients. The maximum allowed number is 1.',
                $exception->getPrevious()?->getMessage()
            );

            return;
        }
        static::fail('The token has been decrypted.');
    }
}
