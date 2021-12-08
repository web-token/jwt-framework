<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Encryption;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @internal
 */
final class JWEComputationTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (! class_exists(JWEBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-encryption" is not installed.');
        }
    }

    /**
     * @test
     */
    public function iCanCreateAndLoadAToken(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);

        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);

        /** @var JWEBuilder $builder */
        $builder = $container->get('jose.jwe_builder.builder1');

        /** @var JWEDecrypter $loader */
        $loader = $container->get('jose.jwe_decrypter.loader1');

        $serializer = new CompactSerializer();

        $jwe = $builder
            ->create()
            ->withPayload('Hello World!')
            ->withSharedProtectedHeader([
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
            ])
            ->addRecipient($jwk)
            ->build()
        ;
        $token = $serializer->serialize($jwe, 0);

        $loaded = $serializer->unserialize($token);
        static::assertTrue($loader->decryptUsingKey($loaded, $jwk, 0));
        static::assertSame('Hello World!', $loaded->getPayload());
    }
}
