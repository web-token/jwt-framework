<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilderInterface;
use Jose\SelectiveDisclosure\Disclosable;
use Jose\SelectiveDisclosure\SDJWT;
use Jose\SelectiveDisclosure\SDJWTHolder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * RFC 9901 sections 4.3 and 7.2: the Key Binding JWT created by the Holder.
 *
 * @internal
 */
final class SDJWTHolderTest extends SelectiveDisclosureTestCase
{
    #[Test]
    public function theHolderBindsThePresentationToItsKey(): void
    {
        $presentation = self::issued()->select(['given_name'], ['address', 'locality']);

        $bound = self::holder()->present($presentation, self::holderKey(), [
            'alg' => 'ES256',
            'kid' => 'holder-key',
        ], self::AUDIENCE, self::NONCE);

        static::assertSame($presentation->getDisclosures(), $bound->getDisclosures());
        static::assertSame($presentation->getIssuerSignedJwt(), $bound->getIssuerSignedJwt());
        [$header, $payload] = explode('.', (string) $bound->getKeyBindingJwt());
        static::assertSame([
            'alg' => 'ES256',
            'kid' => 'holder-key',
            'typ' => 'kb+jwt',
        ], JsonConverter::decode(Base64UrlSafe::decodeNoPadding($header)));
        static::assertSame([
            'nonce' => self::NONCE,
            'aud' => self::AUDIENCE,
            'iat' => self::NOW,
            'sd_hash' => $presentation->getSdHash(),
        ], JsonConverter::decode(Base64UrlSafe::decodeNoPadding($payload)));
    }

    #[Test]
    public function theIssuerTheHolderAndTheVerifierWorkTogether(): void
    {
        $presentation = self::holder()->present(
            self::issued()->select(['given_name'], ['address', 'locality'], ['nationalities', 2]),
            self::holderKey(),
            [
                'alg' => 'ES256',
            ],
            self::AUDIENCE,
            self::NONCE
        );

        $verified = self::verifier(mandatoryClaims: ['iss', 'exp'])->verifyWithKeyBinding(
            $presentation->toString(),
            self::issuerKey()->toPublic(),
            self::AUDIENCE,
            self::NONCE
        );

        static::assertSame(self::canonical([
            'iss' => 'https://issuer.example.com',
            'iat' => self::NOW,
            'exp' => self::NOW + 3600,
            'given_name' => 'John',
            'address' => [
                'locality' => 'Schulpforta',
                'country' => 'DE',
            ],
            'nationalities' => ['FR', 'US'],
            'cnf' => [
                'jwk' => self::holderKey()->toPublic()->all(),
            ],
        ]), self::canonical($verified->getClaims()));
        static::assertSame(self::holderKey()->toPublic()->all(), $verified->getHolderKey()?->all());
    }

    #[Test]
    public function anSdJwtWithKeyBindingCannotBePresentedAgain(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('The SD-JWT already has a Key Binding JWT.');

        self::holder()->present(SDJWT::fromString(self::example('section-5')['presentation']), self::holderKey(), [
            'alg' => 'ES256',
        ], self::AUDIENCE, self::NONCE);
    }

    #[Test]
    public function theHolderKeyIsNotUsedForAnSdJwtThatIsAlreadyBound(): void
    {
        $holder = new SDJWTHolder(new class() implements JWSBuilderInterface {
            public function getSignatureAlgorithmManager(): AlgorithmManager
            {
                throw new LogicException('The builder must not be used.');
            }

            public function withPayload(string $payload, bool $isPayloadDetached = false): JWSBuilderInterface
            {
                throw new LogicException('The builder must not be used.');
            }

            public function withEncodedPayload(string $payload, bool $isPayloadDetached = false): JWSBuilderInterface
            {
                throw new LogicException('The builder must not be used.');
            }

            public function addSignature(JWK $signatureKey, array $protectedHeader, array $header = []): JWSBuilderInterface
            {
                throw new LogicException('The builder must not be used.');
            }

            public function build(): JWS
            {
                throw new LogicException('The builder must not be used.');
            }
        }, self::clock());

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('The SD-JWT already has a Key Binding JWT.');

        $holder->present(SDJWT::fromString(self::example('section-5')['presentation']), self::holderKey(), [
            'alg' => 'ES256',
        ], self::AUDIENCE, self::NONCE);
    }

    /**
     * @param array<string, mixed> $protectedHeader
     */
    #[Test]
    #[DataProvider('invalidProtectedHeaders')]
    public function theProtectedHeaderOfTheKeyBindingJwtIsChecked(array $protectedHeader, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::holder()->present(self::issued(), self::holderKey(), $protectedHeader, self::AUDIENCE, self::NONCE);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidProtectedHeaders(): iterable
    {
        $alg = 'The Key Binding JWT must be signed: the "alg" header parameter must name a signature algorithm.';
        yield 'no alg' => [[], $alg];
        yield 'none' => [[
            'alg' => 'none',
        ], $alg];
        yield 'a MAC algorithm' => [[
            'alg' => 'HS256',
        ], $alg];
        yield 'another type' => [[
            'alg' => 'ES256',
            'typ' => 'JWT',
        ], 'The Key Binding JWT must be of type "kb+jwt".'];
    }

    #[Test]
    public function theTypeOfTheKeyBindingJwtMayBeGiven(): void
    {
        $bound = self::holder()->present(self::issued(), self::holderKey(), [
            'alg' => 'ES256',
            'typ' => 'kb+jwt',
        ], self::AUDIENCE, self::NONCE);

        static::assertTrue(self::verifier()->verifyWithKeyBinding($bound->toString(), self::issuerKey(), self::AUDIENCE, self::NONCE)->hasKeyBinding());
    }

    #[Test]
    public function theCreationTimeComesFromTheClock(): void
    {
        $bound = self::holder(self::NOW + 42)->present(self::issued(), self::holderKey(), [
            'alg' => 'ES256',
        ], self::AUDIENCE, self::NONCE);

        $payload = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(explode('.', (string) $bound->getKeyBindingJwt())[1]));
        static::assertSame(self::NOW + 42, $payload['iat']);
    }

    private static function issued(): SDJWT
    {
        return self::issuer()->issue([
            'iss' => 'https://issuer.example.com',
            'iat' => self::NOW,
            'exp' => self::NOW + 3600,
            'given_name' => new Disclosable('John'),
            'family_name' => new Disclosable('Doe'),
            'address' => new Disclosable([
                'locality' => new Disclosable('Schulpforta'),
                'country' => 'DE',
            ]),
            'nationalities' => ['FR', new Disclosable('DE'), new Disclosable('US')],
            'cnf' => [
                'jwk' => self::holderKey()->toPublic()->all(),
            ],
        ], self::issuerKey(), [
            'alg' => 'ES256',
            'typ' => 'example+sd-jwt',
        ]);
    }
}
