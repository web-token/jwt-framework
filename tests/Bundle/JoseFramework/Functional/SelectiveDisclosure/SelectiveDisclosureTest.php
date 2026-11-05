<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\SelectiveDisclosure;

use DateTimeImmutable;
use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory;
use Jose\Bundle\JoseFramework\Services\JWSLoaderFactory;
use Jose\Bundle\JoseFramework\Services\SDJWTHolderFactory;
use Jose\Bundle\JoseFramework\Services\SDJWTIssuerFactory;
use Jose\Bundle\JoseFramework\Services\SDJWTVerifierFactory;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\SelectiveDisclosure\Disclosable;
use Jose\SelectiveDisclosure\IssuerSignature;
use Jose\SelectiveDisclosure\SDJWTHolder;
use Jose\SelectiveDisclosure\SDJWTIssuer;
use Jose\SelectiveDisclosure\SDJWTVerifier;
use Jose\Tests\Bundle\JoseFramework\TestBundle\Service\SelectiveDisclosureServiceConsumer;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ContainerInterface;
use function count;

/**
 * @internal
 */
final class SelectiveDisclosureTest extends WebTestCase
{
    /**
     * The creation time of the Key Binding JWTs of the examples of RFC 9901.
     */
    private const KEY_BINDING_ISSUED_AT = 1748537244;

    private static ?JWK $holderKey = null;

    #[Test]
    public function theFactoriesAreAvailable(): void
    {
        $container = self::container();

        static::assertTrue($container->has(SDJWTIssuerFactory::class));
        static::assertTrue($container->has(SDJWTHolderFactory::class));
        static::assertTrue($container->has(SDJWTVerifierFactory::class));
    }

    #[Test]
    public function theServicesFromTheConfigurationAreAvailable(): void
    {
        $container = self::container();

        static::assertInstanceOf(SDJWTIssuer::class, $container->get('jose.sd_jwt_issuer.issuer1'));
        static::assertInstanceOf(SDJWTHolder::class, $container->get('jose.sd_jwt_holder.holder1'));
        static::assertInstanceOf(SDJWTVerifier::class, $container->get('jose.sd_jwt_verifier.verifier1'));
    }

    #[Test]
    public function theServicesFromTheConfigurationCanBeAutowired(): void
    {
        $container = self::container();

        $consumer = $container->get(SelectiveDisclosureServiceConsumer::class);

        static::assertInstanceOf(SelectiveDisclosureServiceConsumer::class, $consumer);
        static::assertSame($container->get('jose.sd_jwt_issuer.issuer1'), $consumer->getIssuer());
        static::assertSame($container->get('jose.sd_jwt_holder.holder1'), $consumer->getHolder());
        static::assertSame($container->get('jose.sd_jwt_verifier.verifier1'), $consumer->getVerifier());
    }

    #[Test]
    public function anSdJwtIsIssuedPresentedAndVerifiedWithTheServicesFromTheConfiguration(): void
    {
        $consumer = self::container()->get(SelectiveDisclosureServiceConsumer::class);
        static::assertInstanceOf(SelectiveDisclosureServiceConsumer::class, $consumer);

        $sdJwt = $consumer->getIssuer()
            ->issue(self::claims(), self::issuerKey(), [
                'alg' => 'ES256',
                'typ' => 'example+sd-jwt',
            ]);
        $presentation = $consumer->getHolder()
            ->present(
                $sdJwt->select(['given_name']),
                self::holderKey(),
                [
                    'alg' => 'ES256',
                ],
                'https://verifier.example.org',
                'nonce'
            );
        $verified = $consumer->getVerifier()
            ->verifyWithKeyBinding(
                $presentation->toString(),
                self::issuerKey()->toPublic(),
                'https://verifier.example.org',
                'nonce'
            );

        static::assertSame('John', $verified->getClaims()['given_name']);
        static::assertArrayNotHasKey('family_name', $verified->getClaims());
        static::assertTrue($verified->hasKeyBinding());
    }

    /**
     * A verifier reads the Issuer-signed JWTs in the serializations of its "serializers" option, the compact one only
     * by default.
     */
    #[Test]
    public function aJsonSdJwtIsVerifiedByAVerifierThatReadsTheJsonSerializations(): void
    {
        $container = self::container();
        $consumer = $container->get(SelectiveDisclosureServiceConsumer::class);
        static::assertInstanceOf(SelectiveDisclosureServiceConsumer::class, $consumer);
        $jsonVerifier = $container->get('jose.sd_jwt_verifier.verifier2');
        static::assertInstanceOf(SDJWTVerifier::class, $jsonVerifier);

        $sdJwt = $consumer->getIssuer()
            ->issueJson(self::claims(), new IssuerSignature(self::issuerKey(), [
                'alg' => 'ES256',
                'typ' => 'example+sd-jwt',
            ]));
        $presentation = $consumer->getHolder()
            ->present(
                $sdJwt->select(['given_name']),
                self::holderKey(),
                [
                    'alg' => 'ES256',
                ],
                'https://verifier.example.org',
                'nonce'
            );
        $verified = $jsonVerifier->verifyWithKeyBinding(
            $presentation->toString(),
            self::issuerKey()->toPublic(),
            'https://verifier.example.org',
            'nonce'
        );

        static::assertSame(JSONFlattenedSerializer::NAME, $presentation->getSerialization());
        static::assertSame('John', $verified->getClaims()['given_name']);
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The Issuer-signed JWT cannot be verified.');
        $consumer->getVerifier()
            ->verifyWithKeyBinding(
                $presentation->toString(),
                self::issuerKey()->toPublic(),
                'https://verifier.example.org',
                'nonce'
            );
    }

    #[Test]
    public function theVerifierFactoryReadsTheCompactSerializationOnlyByDefault(): void
    {
        $container = self::container();
        $jwsLoaderFactory = $container->get(JWSLoaderFactory::class);
        static::assertInstanceOf(JWSLoaderFactory::class, $jwsLoaderFactory);
        $claimCheckerManagerFactory = $container->get(ClaimCheckerManagerFactory::class);
        static::assertInstanceOf(ClaimCheckerManagerFactory::class, $claimCheckerManagerFactory);
        $example = JsonConverter::decode(file_get_contents(__DIR__ . '/../../../../fixtures/rfc9901/examples.json'));
        static::assertIsArray($example);
        $factory = new SDJWTVerifierFactory(
            $jwsLoaderFactory,
            $claimCheckerManagerFactory,
            new MockClock(new DateTimeImmutable('@' . self::KEY_BINDING_ISSUED_AT))
        );
        $sdJwt = JsonConverter::encode($example['section-8.2']['sd_jwt']);
        $issuerKey = new JWK($example['issuer_key']);

        $verified = $factory->create(['ES256'], serializers: ['jws_compact', 'jws_json_flattened'])
            ->verify($sdJwt, $issuerKey);

        static::assertSame('John', $verified->getClaims()['given_name']);
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The Issuer-signed JWT cannot be verified.');
        $factory->create(['ES256'])
            ->verify($sdJwt, $issuerKey);
    }

    #[Test]
    public function theDecoyDigestsOfTheConfigurationAreAdded(): void
    {
        $consumer = self::container()->get(SelectiveDisclosureServiceConsumer::class);
        static::assertInstanceOf(SelectiveDisclosureServiceConsumer::class, $consumer);

        $sdJwt = $consumer->getIssuer()
            ->issue(self::claims(), self::issuerKey(), [
                'alg' => 'ES256',
                'typ' => 'example+sd-jwt',
            ]);

        $payload = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(explode('.', $sdJwt->getIssuerSignedJwt())[1]));
        static::assertIsArray($payload);
        static::assertGreaterThanOrEqual(2 + 1, count($payload['_sd']));
        static::assertLessThanOrEqual(2 + 3, count($payload['_sd']));
    }

    #[Test]
    public function theIssuerFactoryHasTheDefaultsOfTheLibrary(): void
    {
        $factory = self::container()->get(SDJWTIssuerFactory::class);
        static::assertInstanceOf(SDJWTIssuerFactory::class, $factory);

        $sdJwt = $factory->create(['ES256'])
            ->issue([
                'given_name' => new Disclosable('John'),
            ], self::issuerKey(), [
                'alg' => 'ES256',
            ]);

        $payload = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(explode('.', $sdJwt->getIssuerSignedJwt())[1]));
        static::assertIsArray($payload);
        static::assertSame('sha-256', $payload['_sd_alg']);
        static::assertCount(1, $payload['_sd']);
    }

    /**
     * By default, the verifier accepts a Key Binding JWT up to 300 seconds old and allows no clock drift: the Key
     * Binding JWT of RFC 9901 section 5.2 is checked at the end of the window, after it and one second before its
     * creation.
     */
    #[Test]
    #[DataProvider('keyBindingTimes')]
    public function theVerifierFactoryHasTheDefaultsOfTheLibrary(int $offset, bool $accepted): void
    {
        $container = self::container();
        $jwsLoaderFactory = $container->get(JWSLoaderFactory::class);
        static::assertInstanceOf(JWSLoaderFactory::class, $jwsLoaderFactory);
        $claimCheckerManagerFactory = $container->get(ClaimCheckerManagerFactory::class);
        static::assertInstanceOf(ClaimCheckerManagerFactory::class, $claimCheckerManagerFactory);
        $example = JsonConverter::decode(file_get_contents(__DIR__ . '/../../../../fixtures/rfc9901/examples.json'));
        static::assertIsArray($example);
        $verifier = (new SDJWTVerifierFactory(
            $jwsLoaderFactory,
            $claimCheckerManagerFactory,
            new MockClock(new DateTimeImmutable('@' . (self::KEY_BINDING_ISSUED_AT + $offset)))
        ))->create(['ES256']);

        try {
            $verified = $verifier->verifyWithKeyBinding(
                $example['section-5']['presentation'],
                new JWK($example['issuer_key']),
                'https://verifier.example.org',
                '1234567890'
            );
            static::assertTrue($accepted, 'The Key Binding JWT has been accepted.');
            static::assertTrue($verified->hasKeyBinding());
        } catch (InvalidTokenException $exception) {
            static::assertFalse($accepted, $exception->getMessage());
        }
    }

    /**
     * @return iterable<string, array{int, bool}>
     */
    public static function keyBindingTimes(): iterable
    {
        yield 'at the end of the window' => [300, true];
        yield 'after the window' => [301, false];
        yield 'one second before its creation' => [-1, false];
    }

    #[Test]
    public function theVerifierAppliesTheCheckersOfTheConfiguration(): void
    {
        $container = self::container();
        $verifier = $container->get('jose.sd_jwt_verifier.verifier1');
        static::assertInstanceOf(SDJWTVerifier::class, $verifier);
        $issuer = $container->get('jose.sd_jwt_issuer.issuer1');
        static::assertInstanceOf(SDJWTIssuer::class, $issuer);

        $withoutIssuer = $issuer->issue([
            'given_name' => new Disclosable('John'),
        ], self::issuerKey(), [
            'alg' => 'ES256',
            'typ' => 'example+sd-jwt',
        ]);
        $untyped = $issuer->issue(self::claims(), self::issuerKey(), [
            'alg' => 'ES256',
            'typ' => 'JWT',
        ]);
        $factory = $container->get(SDJWTIssuerFactory::class);
        static::assertInstanceOf(SDJWTIssuerFactory::class, $factory);
        $withSha512 = $factory->create(['ES256'], 'sha-512')
            ->issue(self::claims(), self::issuerKey(), [
                'alg' => 'ES256',
                'typ' => 'example+sd-jwt',
            ]);

        foreach ([
            'The following claims are mandatory: iss.' => $withoutIssuer,
            'Unsupported type.' => $untyped,
            'The hash algorithm "sha-512" of the SD-JWT is not accepted.' => $withSha512,
        ] as $message => $sdJwt) {
            try {
                $verifier->verify($sdJwt->toString(), self::issuerKey()->toPublic());
                static::fail('The SD-JWT has been accepted.');
            } catch (InvalidTokenException $exception) {
                $messages = [];
                for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
                    $messages[] = $current->getMessage();
                }
                static::assertContains($message, $messages);
            }
        }
    }

    private static function container(): ContainerInterface
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        return $client->getContainer();
    }

    /**
     * @return array<string, mixed>
     */
    private static function claims(): array
    {
        return [
            'iss' => 'https://issuer.example.com',
            'iat' => time(),
            'exp' => time() + 3600,
            'given_name' => new Disclosable('John'),
            'family_name' => new Disclosable('Doe'),
            'cnf' => [
                'jwk' => self::holderKey()->toPublic()->all(),
            ],
        ];
    }

    private static function issuerKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);
    }

    private static function holderKey(): JWK
    {
        self::$holderKey ??= (new JWKFactory())->ec('P-256');

        return self::$holderKey;
    }
}
