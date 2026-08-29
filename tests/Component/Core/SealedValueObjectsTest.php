<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\Signature;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

/**
 * The value objects of the library will be final and readonly in 5.0.0. Unlike the services, they have no interface
 * to decorate in place of the inheritance: the deprecation notice is the only warning their subclasses get before the
 * change.
 *
 * @internal
 */
final class SealedValueObjectsTest extends TestCase
{
    #[Test]
    #[DataProvider('valueObjects')]
    public function extendingAValueObjectIsDeprecatedButBuildingItIsNot(
        callable $extended,
        callable $plain,
        string $sealedClass
    ): void {
        $deprecations = $this->collectDeprecations($extended);

        static::assertCount(1, $deprecations);
        static::assertStringContainsString($sealedClass, $deprecations[0]);
        static::assertStringContainsString('final and readonly in 5.0.0', $deprecations[0]);
        static::assertSame([], $this->collectDeprecations($plain));
    }

    /**
     * @return iterable<string, array{callable(): object, callable(): object, class-string}>
     */
    public static function valueObjects(): iterable
    {
        yield 'JWK' => [
            static fn (): JWK => new class([
                'kty' => 'oct',
            ]) extends JWK {},
            static fn (): JWK => new JWK([
                'kty' => 'oct',
            ]),
            JWK::class,
        ];

        yield 'JWKSet' => [
            static fn (): JWKSet => new class([]) extends JWKSet {},
            static fn (): JWKSet => new JWKSet([]),
            JWKSet::class,
        ];

        yield 'JWS' => [
            static fn (): JWS => new class('payload') extends JWS {},
            static fn (): JWS => new JWS('payload'),
            JWS::class,
        ];

        yield 'JWE' => [
            static fn (): JWE => new class('ciphertext', 'iv', 'tag') extends JWE {},
            static fn (): JWE => new JWE('ciphertext', 'iv', 'tag'),
            JWE::class,
        ];

        yield 'Signature' => [
            static fn (): Signature => new class('signature', [], null, []) extends Signature {},
            static fn (): Signature => new Signature('signature', [], null, []),
            Signature::class,
        ];
    }

    /**
     * @param callable(): object $callable
     *
     * @return string[]
     */
    private function collectDeprecations(callable $callable): array
    {
        $deprecations = [];
        set_error_handler(static function (int $type, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callable();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
