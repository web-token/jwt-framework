<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\None;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\None as DeprecatedNone;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Unsecured\Signature\None;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class NoneSignatureTest extends TestCase
{
    #[Test]
    public function noneSignAndVerifyAlgorithm(): void
    {
        $key = new JWK([
            'kty' => 'none',
        ]);

        $none = new None();
        $data = 'Live long and Prosper.';

        $signature = $none->sign($key, $data);

        static::assertSame('', $signature);
        static::assertTrue($none->verify($key, $data, $signature));
    }

    #[Test]
    public function invalidKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Wrong key type.');
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $none = new None();
        $data = 'Live long and Prosper.';

        $none->sign($key, $data);
    }

    #[Test]
    public function verificationWithAnInvalidKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Wrong key type.');
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $none = new None();

        $none->verify($key, 'Live long and Prosper.', '');
    }

    #[Test]
    public function noneSignAndVerifyComplete(): void
    {
        $jwk = new JWK([
            'kty' => 'none',
        ]);

        $jwsBuilder = new JWSBuilder(new AlgorithmManager([new None()]));
        $serializer = new CompactSerializer();
        $jws = $jwsBuilder
            ->withPayload('Live long and Prosper.')
            ->addSignature($jwk, [
                'alg' => 'none',
            ])
            ->build();

        static::assertSame(1, $jws->countSignatures());

        $compact = $serializer->serialize($jws, 0);
        static::assertIsString($compact);

        $result = $serializer->unserialize($compact);

        static::assertSame('Live long and Prosper.', $result->getPayload());
        static::assertSame(1, $result->countSignatures());
        static::assertTrue($result->getSignature(0)->hasProtectedHeaderParameter('alg'));
        static::assertSame('none', $result->getSignature(0)->getProtectedHeaderParameter('alg'));
    }

    /**
     * The algorithm shipped by the library until 5.0.0 is now an empty subclass of the one of the
     * web-token/jwt-unsecured package, so that the applications that migrate can mix both classes.
     */
    #[Test]
    #[IgnoreDeprecations]
    public function theDeprecatedClassOfTheLibraryIsStillUsable(): void
    {
        $key = new JWK([
            'kty' => 'none',
        ]);

        $none = new DeprecatedNone();

        static::assertInstanceOf(None::class, $none);
        static::assertSame('none', $none->name());
        static::assertSame('', $none->sign($key, 'Live long and Prosper.'));
        static::assertTrue($none->verify($key, 'Live long and Prosper.', ''));
    }
}
