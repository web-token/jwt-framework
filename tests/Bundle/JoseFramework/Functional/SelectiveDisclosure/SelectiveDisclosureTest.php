<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\SelectiveDisclosure;

use Jose\Bundle\JoseFramework\Services\SDJWTHolderFactory;
use Jose\Bundle\JoseFramework\Services\SDJWTIssuerFactory;
use Jose\Bundle\JoseFramework\Services\SDJWTVerifierFactory;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\SelectiveDisclosure\Disclosable;
use Jose\SelectiveDisclosure\SDJWTHolder;
use Jose\SelectiveDisclosure\SDJWTIssuer;
use Jose\SelectiveDisclosure\SDJWTVerifier;
use Jose\Tests\Bundle\JoseFramework\TestBundle\Service\SelectiveDisclosureServiceConsumer;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ContainerInterface;
use function count;

/**
 * @internal
 */
final class SelectiveDisclosureTest extends WebTestCase
{
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
