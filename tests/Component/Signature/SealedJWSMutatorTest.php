<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\Signature;
use PHPUnit\Framework\Attributes\Test;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

/**
 * A JWS is assembled by the builder and by the serializers, the only objects allowed to append a signature to it.
 * Calling the mutator from anywhere else is deprecated, so that a token returned by a loader is not modified after
 * its signatures have been verified.
 *
 * @internal
 */
final class SealedJWSMutatorTest extends SignatureTestCase
{
    private const PAYLOAD = 'Live long and prosper.';

    #[Test]
    public function addingASignatureFromOutsideTheLibraryIsDeprecated(): void
    {
        $jws = new JWS(self::PAYLOAD);

        $deprecations = $this->collectDeprecations(static function () use ($jws): void {
            $jws->addSignature('signature', [], null);
        });

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'The method "Jose\Component\Signature\JWS::addSignature()" is internal to the library.',
            $deprecations[0]
        );
    }

    #[Test]
    public function theBuilderAndTheSerializersAssembleAJWSWithoutDeprecation(): void
    {
        $jws = null;
        $deprecations = $this->collectDeprecations(function () use (&$jws): void {
            $jws = $this->getJWSBuilderFactory()
                ->create(['HS256'])
                ->withPayload(self::PAYLOAD)
                ->addSignature($this->getKey(), [
                    'alg' => 'HS256',
                ])
                ->build();
        });

        static::assertSame([], $deprecations);
        static::assertInstanceOf(JWS::class, $jws);

        $token = $this->getJWSSerializerManager()
            ->serialize('jws_compact', $jws, 0);
        $unserialized = null;
        $deprecations = $this->collectDeprecations(function () use ($token, &$unserialized): void {
            $unserialized = $this->getJWSSerializerManager()
                ->unserialize($token);
        });

        static::assertSame([], $deprecations);
        static::assertInstanceOf(JWS::class, $unserialized);
        static::assertSame(self::PAYLOAD, $unserialized->getPayload());
    }

    #[Test]
    public function splittingAJWSDoesNotEmitADeprecation(): void
    {
        $jws = $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->withPayload(self::PAYLOAD)
            ->addSignature($this->getKey(), [
                'alg' => 'HS256',
            ])
            ->build();

        $split = null;
        $deprecations = $this->collectDeprecations(static function () use ($jws, &$split): void {
            $split = $jws->split();
        });

        static::assertSame([], $deprecations);
        static::assertCount(1, $split);
    }

    #[Test]
    public function aProtectedHeaderWithoutItsEncodedFormIsDiscardedAndDeprecated(): void
    {
        $signature = null;
        $deprecations = $this->collectDeprecations(static function () use (&$signature): void {
            $signature = new Signature('signature', [
                'alg' => 'HS256',
            ], null, []);
        });

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'Passing a protected header to "Jose\Component\Signature\Signature" without its encoded form is deprecated',
            $deprecations[0]
        );
        static::assertInstanceOf(Signature::class, $signature);
        static::assertSame([], $signature->getProtectedHeader());
        static::assertNull($signature->getEncodedProtectedHeader());
    }

    #[Test]
    public function aSignatureWithoutAnyProtectedHeaderIsNotDeprecated(): void
    {
        $deprecations = $this->collectDeprecations(static function (): void {
            new Signature('signature', [], null, [
                'alg' => 'HS256',
            ]);
        });

        static::assertSame([], $deprecations);
    }

    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
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
