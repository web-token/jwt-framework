<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\ECDSA;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\Ecc\KoblitzCurve;
use Jose\Component\KeyManagement\Analyzer\ES256KKeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256K;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
use Jose\Experimental\Signature\ES256K as ExperimentalES256K;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The "ES256K" algorithm of RFC 8812, in the library since 4.3; the experimental class is a deprecated subclass.
 *
 * @internal
 */
final class ES256KSignatureTest extends TestCase
{
    #[Test]
    public function es256KVerify(): void
    {
        $key = $this->getKey();
        $algorithm = new ES256K();
        $data = 'Hello';

        static::assertTrue($algorithm->verify($key, $data, hex2bin(
            '9c75b9d171d9690a37f2474d4bfab5c234911cb150950ea5cbfc9aedda5ec360725cc47978de95b4efb2a3ed617c7b36b1cd0a26b536662a79d0f3ae873a7924'
        )));
    }

    #[Test]
    public function es256KSignAndVerify(): void
    {
        $key = $this->getKey();
        $algorithm = new ES256K();
        $data = 'Hello';

        static::assertSame('ES256K', $algorithm->name());

        $signature = $algorithm->sign($key, $data);

        static::assertTrue($algorithm->verify($key, $data, $signature));
    }

    /**
     * @return iterable<string, array{JWSSerializer}>
     */
    public static function serializers(): iterable
    {
        yield 'compact' => [new CompactSerializer()];
        yield 'flattened' => [new JSONFlattenedSerializer()];
        yield 'general' => [new JSONGeneralSerializer()];
    }

    #[Test]
    #[DataProvider('serializers')]
    public function aTokenIsSignedAndVerifiedThroughEverySerializer(JWSSerializer $serializer): void
    {
        $key = (new JWKFactory())->ec('secp256k1', [
            'alg' => 'ES256K',
        ]);
        $manager = new AlgorithmManager([new ES256K()]);

        $jws = (new JWSBuilder($manager))
            ->withPayload('{"iss":"me"}')
            ->addSignature($key, [
                'alg' => 'ES256K',
            ])
            ->build();
        $loaded = $serializer->unserialize($serializer->serialize($jws, 0));

        static::assertTrue((new JWSVerifier($manager))->verify($loaded, $key->toPublic(), 0)->isVerified());
        static::assertSame('ES256K', $loaded->getSignature(0)->getProtectedHeaderParameter('alg'));
    }

    #[Test]
    #[IgnoreDeprecations]
    public function theExperimentalClassIsADeprecatedSubclassOfTheLibraryOne(): void
    {
        $algorithm = new ExperimentalES256K();

        static::assertInstanceOf(ES256K::class, $algorithm);
        static::assertSame('ES256K', $algorithm->name());
        static::assertTrue($algorithm->verify($this->getKey(), 'Hello', (new ES256K())->sign($this->getKey(), 'Hello')));
    }

    #[Test]
    public function theSecp256k1GeneratorIsOnTheCurve(): void
    {
        $curve = KoblitzCurve::secp256k1();
        $generator = $curve->getGenerator();

        static::assertTrue($curve->contains($generator->getX(), $generator->getY()));
        static::assertSame(256, $curve->getSize());
    }

    #[Test]
    public function theKeyAnalyzerAcceptsTheKeyAndRejectsAPointOffTheCurve(): void
    {
        $bag = new MessageBag();
        (new ES256KKeyAnalyzer())->analyze($this->getKey(), $bag);
        static::assertCount(0, $bag);

        $values = $this->getKey()
            ->all();
        $values['y'] = $values['x'];
        $bag = new MessageBag();
        (new ES256KKeyAnalyzer())->analyze(new JWK($values), $bag);
        static::assertCount(1, $bag);
        static::assertSame('Invalid key. The point is not on the curve.', $bag->all()[0]->getMessage());
    }

    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'secp256k1',
            'd' => Base64UrlSafe::encodeUnpadded(
                hex2bin('D1592A94BBB9B5D94CDC425FC7DA80B6A47863AE973A9D581FD9D8F29690B659')
            ),
            'x' => Base64UrlSafe::encodeUnpadded(
                hex2bin('4B4DF318DE05BB8F3A115BF337F9BCBC55CA14B917B46BCB557D3C9A158D4BE0')
            ),
            'y' => Base64UrlSafe::encodeUnpadded(
                hex2bin('627EB75731A8BBEBC7D9A3C57EC4D7DA2CBA6D2A28E7F45134921861FE1CF5D9')
            ),
        ]);
    }
}
