<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use InvalidArgumentException;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\Signature;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\Attributes\Test;
use const JSON_THROW_ON_ERROR;

/**
 * The tests that assemble a JWS by hand call the mutator reserved to the builder and to the serializers, hence the
 * deprecation they are expected to trigger.
 *
 * @internal
 */
final class JWSTest extends SignatureTestCase
{
    #[Test]
    #[IgnoreDeprecations]
    public function jWS(): void
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = [
            'alg' => 'none',
        ];
        $jws = new JWS(json_encode($claims, JSON_THROW_ON_ERROR), json_encode($claims, JSON_THROW_ON_ERROR));
        $jws = $jws->addSignature('', $header, Base64UrlSafe::encodeUnpadded(json_encode($header)));

        static::assertSame(json_encode($claims, JSON_THROW_ON_ERROR), $jws->getPayload());
        static::assertSame(1, $jws->countSignatures());
        static::assertTrue($jws->getSignature(0)->hasProtectedHeaderParameter('alg'));
        static::assertSame($header, $jws->getSignature(0)->getProtectedHeader());
        static::assertSame('none', $jws->getSignature(0)->getProtectedHeaderParameter('alg'));
        static::assertSame([], $jws->getSignature(0)->getHeader());
    }

    #[Test]
    public function toCompactJSONFailed(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The signature does not exist.');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = new JWS(json_encode($claims, JSON_THROW_ON_ERROR), json_encode($claims, JSON_THROW_ON_ERROR));
        $this->getJWSSerializerManager()
            ->serialize('jws_compact', $jws, 0);
    }

    #[Test]
    public function toFlattenedJSONFailed(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The signature does not exist.');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = new JWS(json_encode($claims, JSON_THROW_ON_ERROR), json_encode($claims, JSON_THROW_ON_ERROR));
        $this->getJWSSerializerManager()
            ->serialize('jws_json_flattened', $jws, 0);
    }

    #[Test]
    public function toJSONFailed(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('No signature.');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = new JWS(json_encode($claims, JSON_THROW_ON_ERROR), json_encode($claims, JSON_THROW_ON_ERROR));
        $this->getJWSSerializerManager()
            ->serialize('jws_json_general', $jws, 0);
    }

    #[Test]
    #[IgnoreDeprecations]
    public function signatureContainsUnprotectedHeader(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'The signature contains unprotected header parameters and cannot be converted into compact JSON'
        );

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = [
            'alg' => 'none',
        ];
        $jws = new JWS(json_encode($claims, JSON_THROW_ON_ERROR), json_encode($claims, JSON_THROW_ON_ERROR));
        $jws = $jws->addSignature('', $header, Base64UrlSafe::encodeUnpadded(json_encode($header)), [
            'foo' => 'bar',
        ]);

        $this->getJWSSerializerManager()
            ->serialize('jws_compact', $jws, 0);
    }

    #[Test]
    #[IgnoreDeprecations]
    public function signatureDoesNotContainHeader(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header "foo" does not exist');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = [
            'alg' => 'none',
        ];
        $jws = new JWS(json_encode($claims, JSON_THROW_ON_ERROR), json_encode($claims, JSON_THROW_ON_ERROR));
        $jws = $jws->addSignature('', $header, Base64UrlSafe::encodeUnpadded(json_encode($header)));
        $jws->getSignature(0)
            ->getHeaderParameter('foo');
    }

    #[Test]
    #[IgnoreDeprecations]
    public function signatureDoesNotContainProtectedHeader(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The protected header "foo" does not exist');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = [
            'alg' => 'none',
        ];
        $jws = new JWS(json_encode($claims, JSON_THROW_ON_ERROR), json_encode($claims, JSON_THROW_ON_ERROR));
        $jws = $jws->addSignature('', $header, Base64UrlSafe::encodeUnpadded(json_encode($header)));
        $jws->getSignature(0)
            ->getProtectedHeaderParameter('foo');
    }

    #[Test]
    public function theSignaturesCanBeGivenToTheConstructor(): void
    {
        $first = new Signature('first', [
            'alg' => 'HS256',
        ], 'eyJhbGciOiJIUzI1NiJ9', []);
        $second = new Signature('second', [], null, [
            'alg' => 'none',
        ]);

        $jws = new JWS('payload', 'cGF5bG9hZA', false, [
            3 => $first,
            7 => $second,
        ]);

        static::assertSame(2, $jws->countSignatures());
        static::assertSame([$first, $second], $jws->getSignatures());
        static::assertSame($first, $jws->getSignature(0));
        static::assertSame($second, $jws->getSignature(1));
    }

    #[Test]
    #[IgnoreDeprecations]
    public function aSignatureAddedToATokenBuiltWithItsSignaturesLeavesThatTokenUnchanged(): void
    {
        $first = new Signature('first', [], null, [
            'alg' => 'none',
        ]);
        $jws = new JWS('payload', 'cGF5bG9hZA', false, [$first]);

        $withSecond = $jws->addSignature('second', [], null, [
            'alg' => 'none',
        ]);

        static::assertSame([$first], $jws->getSignatures());
        static::assertSame(2, $withSecond->countSignatures());
        static::assertSame($first, $withSecond->getSignature(0));
        static::assertSame('second', $withSecond->getSignature(1)->getSignature());
    }

    #[DataProvider('invalidSignatureLists')]
    #[Test]
    public function theSignaturesGivenToTheConstructorMustBeSignatureObjects(mixed $signatures): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The signatures must be a list of Signature objects.');

        new JWS('payload', 'cGF5bG9hZA', false, $signatures);
    }

    public static function invalidSignatureLists(): iterable
    {
        yield 'null' => [null];
        yield 'a string' => ['signature'];
        yield 'a list holding something else than a signature' => [
            [new Signature('first', [], null, [
                'alg' => 'none',
            ]), 'second'],
        ];
    }
}
