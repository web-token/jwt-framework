<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use PHPUnit\Framework\Attributes\Test;
use const E_USER_DEPRECATED;

/**
 * The builder is a shared service that accumulates no state: the methods that set the payload or add a
 * signature return a new object, the checks that involve several of them are performed by build() and the
 * order of the calls is therefore irrelevant.
 *
 * @internal
 */
final class JWSBuilderImmutabilityTest extends SignatureTestCase
{
    private const PAYLOAD = 'Live long and prosper.';

    #[Test]
    public function theAccumulationMethodsDoNotModifyTheReceiver(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()
            ->create(['HS256']);

        $jwsBuilder->withPayload(self::PAYLOAD)
            ->addSignature($this->getKey(), [
                'alg' => 'HS256',
            ]);

        $jws = $jwsBuilder->withPayload('Another payload.')
            ->addSignature($this->getKey(), [
                'alg' => 'HS256',
            ])
            ->build();

        static::assertCount(1, $jws->getSignatures());
        static::assertSame('Another payload.', $jws->getPayload());
    }

    #[Test]
    public function theSignatureCanBeAddedBeforeThePayload(): void
    {
        $jws = $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->addSignature($this->getKey(), [
                'alg' => 'HS256',
            ])
            ->withPayload(self::PAYLOAD)
            ->build();

        static::assertSame(self::PAYLOAD, $jws->getPayload());
        static::assertTrue(
            $this->getJWSVerifierFactory()
                ->create(['HS256'])
                ->verifyWithKey($jws, $this->getKey(), 0)
        );
    }

    #[Test]
    public function theEncodedPayloadCanBeSetAfterTheSignature(): void
    {
        $jws = $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->addSignature($this->getKey(), [
                'alg' => 'HS256',
            ])
            ->withEncodedPayload('TGl2ZSBsb25nIGFuZCBwcm9zcGVyLg')
            ->build();

        static::assertSame(self::PAYLOAD, $jws->getPayload());
        static::assertSame(
            'eyJhbGciOiJIUzI1NiJ9.TGl2ZSBsb25nIGFuZCBwcm9zcGVyLg.A56oyIOTJjW_wGKMAPEoYyb83dkoiGi7WtGul4K2ls4',
            $this->getJWSSerializerManager()
                ->serialize('jws_compact', $jws, 0)
        );
    }

    #[Test]
    public function theCreateMethodIsDeprecatedAndReturnsAPristineBuilder(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->withPayload(self::PAYLOAD);

        $reset = null;
        $deprecations = $this->collectDeprecations(static function () use ($jwsBuilder, &$reset): void {
            $reset = $jwsBuilder->create();
        });

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'The method "Jose\Component\Signature\JWSBuilder::create()" is deprecated and will be removed in 5.0.0.',
            $deprecations[0]
        );
        static::assertInstanceOf(JWSBuilder::class, $reset);
        static::assertNotSame($jwsBuilder, $reset);
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
