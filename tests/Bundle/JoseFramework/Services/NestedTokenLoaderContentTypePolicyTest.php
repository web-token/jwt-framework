<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingSuccessEvent;
use Jose\Bundle\JoseFramework\Services\NestedTokenLoader;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\NestedToken\NestedTokenLoader as BaseNestedTokenLoader;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;
use function array_map;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use const E_USER_DEPRECATED;

/**
 * The deprecated event dispatching nested token loader of the bundle passes a fourth argument to the loader of the
 * library: what it does with a token whose "cty" header parameter is outside the protected header. With its three
 * arguments only, it behaves as before.
 *
 * @internal
 */
final class NestedTokenLoaderContentTypePolicyTest extends TestCase
{
    private const CLAIMS = '{"iss":"issuer.example","sub":"alice"}';

    private const ENCRYPTION_KEY = 'kek-A128KW-01234';

    private const SIGNATURE_KEY = 'the HS256 key of the issuer of the token';

    private const DEPRECATION = 'Since web-token/jwt-library 4.3.0: Loading a nested token whose "cty" header parameter is not in the protected header is deprecated and "%s" will refuse such a token by default in 5.0.0, as the unprotected headers of a JWE are not authenticated. Have the issuer set "cty" in the protected header, or pass true as the third argument of the constructor to keep loading these tokens, or false to refuse them. With the bundle, set the "allow_unprotected_content_type" option of the nested token loader.';

    /**
     * @param list<bool> $policy
     * @param list<string> $expectedDeprecations
     * @param class-string $expectedEvent
     */
    #[Test]
    #[DataProvider('policies')]
    public function theFourthArgumentIsPassedToTheLoaderOfTheLibrary(
        array $policy,
        array $expectedDeprecations,
        ?string $expectedError,
        string $expectedEvent
    ): void {
        $dispatcher = new CollectingEventDispatcher();
        $loader = new NestedTokenLoader(self::jweLoader(), self::jwsLoader(), $dispatcher, ...$policy);
        $token = self::token();

        $error = null;
        $deprecations = $this->collectDeprecations(static function () use ($loader, $token, &$error): void {
            try {
                $loader->loadAndVerify(
                    $token,
                    new JWKSet([self::octetKey(self::ENCRYPTION_KEY)]),
                    new JWKSet([self::octetKey(self::SIGNATURE_KEY)])
                );
            } catch (Throwable $throwable) {
                $error = $throwable->getMessage();
            }
        });

        static::assertSame([$expectedDeprecations, $expectedError], [$deprecations, $error]);
        static::assertSame(
            [$expectedEvent],
            array_map(static fn (object $event): string => $event::class, $dispatcher->events())
        );
    }

    /**
     * @return iterable<string, array{list<bool>, list<string>, string|null, class-string}>
     */
    public static function policies(): iterable
    {
        yield 'three arguments' => [
            [],
            [sprintf(self::DEPRECATION, BaseNestedTokenLoader::class)],
            null,
            NestedTokenLoadingSuccessEvent::class,
        ];
        yield 'true' => [[true], [], null, NestedTokenLoadingSuccessEvent::class];
        yield 'false' => [
            [false],
            [],
            'The "cty" header parameter must be in the protected header.',
            NestedTokenLoadingFailureEvent::class,
        ];
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

    private static function jweLoader(): JWELoader
    {
        return new JWELoader(
            new JWESerializerManager([new JSONFlattenedSerializer()]),
            new JWEDecrypter(new AlgorithmManager([new A128KW(), new A128GCM()])),
            null
        );
    }

    private static function jwsLoader(): JWSLoader
    {
        return new JWSLoader(
            new JWSSerializerManager([new CompactSerializer()]),
            new JWSVerifier(new AlgorithmManager([new HS256()])),
            null
        );
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
