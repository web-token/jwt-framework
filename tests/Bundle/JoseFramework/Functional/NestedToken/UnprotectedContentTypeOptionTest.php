<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\NestedToken;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Tests\Bundle\JoseFramework\IsolatedKernel;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use const E_USER_DEPRECATED;

/**
 * The "allow_unprotected_content_type" option of a nested token loader sets what the loader does with a token whose
 * "cty" header parameter is outside the protected header: true loads it, false refuses it. When the option is not set,
 * the token loads with a deprecation, as 5.0.0 refuses it by default.
 *
 * @internal
 */
final class UnprotectedContentTypeOptionTest extends TestCase
{
    private const CLAIMS = '{"iss":"issuer.example","sub":"alice"}';

    private const ENCRYPTION_KEY = 'kek-A128KW-01234';

    private const SIGNATURE_KEY = 'the HS256 key of the issuer of the token';

    private const DEPRECATION = 'Since web-token/jwt-library 4.3.0: Loading a nested token whose "cty" header parameter is not in the protected header is deprecated and "%s" will refuse such a token by default in 5.0.0, as the unprotected headers of a JWE are not authenticated. Have the issuer set "cty" in the protected header, or pass true as the third argument of the constructor to keep loading these tokens, or false to refuse them. With the bundle, set the "allow_unprotected_content_type" option of the nested token loader.';

    private ?IsolatedKernel $kernel = null;

    protected function tearDown(): void
    {
        if ($this->kernel !== null) {
            $this->kernel->shutdown();
            (new Filesystem())->remove($this->kernel->getVarDir());
            $this->kernel = null;
        }

        parent::tearDown();
    }

    #[Test]
    public function theLoaderRefusesTheTokenWhenTheOptionIsFalse(): void
    {
        $loader = $this->getLoader([
            'allow_unprotected_content_type' => false,
        ]);
        $token = self::token();

        $this->expectException(InvalidHeaderParameterException::class);
        $this->expectExceptionMessage('The "cty" header parameter must be in the protected header.');

        self::load($loader, $token);
    }

    #[Test]
    public function theLoaderLoadsTheTokenWithoutDeprecationWhenTheOptionIsTrue(): void
    {
        $loader = $this->getLoader([
            'allow_unprotected_content_type' => true,
        ]);
        $token = self::token();

        $deprecations = $this->collectDeprecations(static function () use ($loader, $token): void {
            static::assertSame(self::CLAIMS, self::load($loader, $token));
        });

        static::assertSame([], $deprecations);
    }

    #[Test]
    public function theLoaderLoadsTheTokenWithADeprecationWhenTheOptionIsNotSet(): void
    {
        $loader = $this->getLoader([]);
        $token = self::token();

        $deprecations = $this->collectDeprecations(static function () use ($loader, $token): void {
            static::assertSame(self::CLAIMS, self::load($loader, $token));
        });

        static::assertSame([sprintf(self::DEPRECATION, NestedTokenLoader::class)], $deprecations);
    }

    /**
     * @param array<string, bool> $options
     */
    private function getLoader(array $options): NestedTokenLoader
    {
        $this->kernel = new IsolatedKernel(static function (ContainerBuilder $container) use ($options): void {
            $container->loadFromExtension('jose', [
                'nested_token' => [
                    'loaders' => [
                        'unprotected_cty' => [
                            'signature_algorithms' => ['HS256'],
                            'encryption_algorithms' => ['A128KW', 'A128GCM'],
                            'jws_serializers' => ['jws_compact'],
                            'jwe_serializers' => ['jwe_json_flattened'],
                            'is_public' => true,
                        ] + $options,
                    ],
                ],
            ]);
        });
        $this->kernel->boot();

        $service = $this->kernel->getContainer()
            ->get('jose.nested_token_loader.unprotected_cty');
        static::assertInstanceOf(NestedTokenLoader::class, $service);

        return $service;
    }

    /**
     * A JSON flattened JWE whose "cty" header parameter is in the shared unprotected header.
     */
    private static function token(): string
    {
        $jws = (new JWSBuilder(new AlgorithmManager([new HS256()])))
            ->withPayload(self::CLAIMS)
            ->addSignature(self::octetKey(self::SIGNATURE_KEY), [
                'alg' => 'HS256',
            ])
            ->build();
        $jwe = (new JWEBuilder(new AlgorithmManager([new A128KW(), new A128GCM()])))
            ->withPayload((new CompactSerializer())->serialize($jws, 0))
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128GCM',
            ])
            ->withSharedHeader([
                'cty' => 'JWT',
            ])
            ->addRecipient(self::octetKey(self::ENCRYPTION_KEY))
            ->build();

        return (new JSONFlattenedSerializer())->serialize($jwe, 0);
    }

    /**
     * Returns the payload of the nested JWS.
     */
    private static function load(NestedTokenLoader $loader, string $token): ?string
    {
        return $loader
            ->loadAndVerify(
                $token,
                new JWKSet([self::octetKey(self::ENCRYPTION_KEY)]),
                new JWKSet([self::octetKey(self::SIGNATURE_KEY)])
            )
            ->getJws()
            ->getPayload();
    }

    private static function octetKey(string $secret): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded($secret),
        ]);
    }

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $type, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
