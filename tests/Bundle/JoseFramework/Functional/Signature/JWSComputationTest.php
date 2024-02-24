<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @internal
 */
final class JWSComputationTest extends WebTestCase
{
    #[Test]
    public static function createAndLoadAToken(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);

        /** @var JWSBuilder $builder */
        $builder = $container->get('jose.jws_builder.builder1');

        /** @var JWSVerifier $loader */
        $loader = $container->get('jose.jws_verifier.loader1');

        $serializer = new CompactSerializer();

        $jws = $builder
            ->create()
            ->withPayload('Hello World!')
            ->addSignature($jwk, [
                'alg' => 'HS256',
            ])
            ->build();
        $token = $serializer->serialize($jws, 0);

        $loaded = $serializer->unserialize($token);
        static::assertTrue($loader->verifyWithKey($loaded, $jwk, 0));
    }
}
