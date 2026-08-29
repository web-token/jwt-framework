<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\HS256;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function iterator_to_array;
use function restore_error_handler;
use function set_error_handler;
use function usort;
use const E_USER_DEPRECATED;

/**
 * The typed accessors of the JWK assert the type of a parameter once, so that the callers stop writing the "has()
 * then get() then is_string()" dance. The internal helpers of the JWKSet that were only public because of the way
 * they were used are deprecated, and the iterator is documented as the public contract it is.
 *
 * @internal
 */
final class JWKTypedAccessorsTest extends TestCase
{
    #[Test]
    public function theTypedAccessorsReturnTheParameters(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
            'alg' => 'HS256',
            'use' => 'sig',
        ]);

        static::assertSame('oct', $jwk->kty());
        static::assertSame('HS256', $jwk->alg());
        static::assertSame('sig', $jwk->use());
        static::assertSame('GawgguFyGrWKav7AX4VKUg', $jwk->getString('k'));
    }

    #[Test]
    public function theOptionalAccessorsReturnNullWhenTheParameterIsAbsent(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
        ]);

        static::assertNull($jwk->alg());
        static::assertNull($jwk->use());
        static::assertNull($jwk->find('kid'));
        static::assertSame('GawgguFyGrWKav7AX4VKUg', $jwk->find('k'));
    }

    #[Test]
    public function anAbsentParameterCannotBeReadAsAString(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The value identified by "kid" does not exist.');

        $jwk->getString('kid');
    }

    #[Test]
    public function aParameterThatIsNotAStringIsRejected(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
            'alg' => 123,
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid key parameter "alg". Should be a string.');

        $jwk->alg();
    }

    #[Test]
    public function aKeySetIsIterable(): void
    {
        $first = new JWK([
            'kty' => 'oct',
            'kid' => 'first',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
        ]);
        $second = new JWK([
            'kty' => 'oct',
            'kid' => 'second',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
        ]);
        $jwkset = new JWKSet([$first, $second]);

        static::assertSame([
            'first' => $first,
            'second' => $second,
        ], iterator_to_array($jwkset->getIterator()));
    }

    #[Test]
    public function sortingTheCandidatesOfSelectKeyIsDeprecated(): void
    {
        $candidates = [[
            'key' => new JWK([
                'kty' => 'oct',
                'k' => 'GawgguFyGrWKav7AX4VKUg',
            ]),
            'ind' => 1,
        ], [
            'key' => new JWK([
                'kty' => 'oct',
                'k' => 'GawgguFyGrWKav7AX4VKUg',
            ]),
            'ind' => 2,
        ]];

        $deprecations = $this->collectDeprecations(static function () use (&$candidates): void {
            usort($candidates, JWKSet::sortKeys(...));
        });

        static::assertNotEmpty($deprecations);
        static::assertStringContainsString(
            'The method "Jose\Component\Core\JWKSet::sortKeys()" is deprecated',
            $deprecations[0]
        );
        static::assertSame(2, $candidates[0]['ind']);
    }

    #[Test]
    public function selectingAKeyDoesNotEmitADeprecation(): void
    {
        $jwkset = new JWKSet([
            new JWK([
                'kty' => 'oct',
                'kid' => 'first',
                'k' => 'GawgguFyGrWKav7AX4VKUg',
            ]),
            new JWK([
                'kty' => 'oct',
                'kid' => 'second',
                'use' => 'sig',
                'k' => 'GawgguFyGrWKav7AX4VKUg',
            ]),
        ]);

        $key = null;
        $deprecations = $this->collectDeprecations(static function () use ($jwkset, &$key): void {
            $key = $jwkset->selectKey('sig');
        });

        static::assertSame([], $deprecations);
        static::assertInstanceOf(JWK::class, $key);
        static::assertSame('second', $key->getString('kid'));
    }

    #[Test]
    public function aMalformedKeyIsSkippedByTheSelectionInsteadOfRejectingTheWholeKeySet(): void
    {
        $jwkset = new JWKSet([
            new JWK([
                'kty' => 'oct',
                'kid' => 'malformed use',
                'use' => 123,
                'k' => 'GawgguFyGrWKav7AX4VKUg',
            ]),
            new JWK([
                'kty' => 'oct',
                'kid' => 'malformed alg',
                'alg' => 123,
                'k' => 'GawgguFyGrWKav7AX4VKUg',
            ]),
            new JWK([
                'kty' => 123,
                'kid' => 'malformed kty',
                'k' => 'GawgguFyGrWKav7AX4VKUg',
            ]),
            new JWK([
                'kty' => 'oct',
                'kid' => 'usable',
                'use' => 'sig',
                'alg' => 'HS256',
                'k' => 'GawgguFyGrWKav7AX4VKUg',
            ]),
        ]);

        $key = $jwkset->selectKey('sig', new HS256());

        static::assertInstanceOf(JWK::class, $key);
        static::assertSame('usable', $key->getString('kid'));
    }

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

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
