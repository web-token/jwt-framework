<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Tests\Component\Signature\Stub\LegacyMacAlgorithm;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class LegacyMacAlgorithmTest extends TestCase
{
    private const PAYLOAD = 'Live long and Prosper.';

    #[Test]
    #[IgnoreDeprecations]
    public function anAlgorithmThatOnlyImplementsMacAlgorithmStillProducesAValidToken(): void
    {
        $algorithm = new LegacyMacAlgorithm();
        $key = $this->getKey();
        $algorithmManager = new AlgorithmManager([$algorithm]);
        $serializer = new CompactSerializer();

        $jws = (new JWSBuilder($algorithmManager))
            ->create()
            ->withPayload(self::PAYLOAD)
            ->addSignature($key, [
                'alg' => 'LEGACY-HS256',
            ])
            ->build();
        $token = $serializer->serialize($jws, 0);

        $loaded = $serializer->unserialize($token);

        static::assertSame(self::PAYLOAD, $loaded->getPayload());
        static::assertTrue((new JWSVerifier($algorithmManager))->verifyWithKey($loaded, $key, 0));
    }

    #[Test]
    public function signingWithAnAlgorithmThatOnlyImplementsMacAlgorithmIsDeprecated(): void
    {
        $this->expectUserDeprecationMessage(
            'Since web-token/jwt-framework 4.3.0: The class "Jose\Tests\Component\Signature\Stub\LegacyMacAlgorithm" implements "Jose\Component\Signature\Algorithm\MacAlgorithm" only. Relying on "Jose\Component\Signature\Algorithm\MacAlgorithm::hash()" is deprecated since 4.3.0 and will not be supported in 5.0.0: implement "Jose\Component\Signature\Algorithm\SignatureAlgorithm" and its sign() method instead.'
        );

        $jws = (new JWSBuilder(new AlgorithmManager([new LegacyMacAlgorithm()])))
            ->create()
            ->withPayload(self::PAYLOAD)
            ->addSignature($this->getKey(), [
                'alg' => 'LEGACY-HS256',
            ])
            ->build();

        static::assertSame(1, $jws->countSignatures());
    }

    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded('foofoofoofoofoofoofoofoofoofoofo'),
        ]);
    }
}
