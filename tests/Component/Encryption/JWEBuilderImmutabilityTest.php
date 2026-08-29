<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWEBuilder;
use PHPUnit\Framework\Attributes\Test;
use const E_USER_DEPRECATED;

/**
 * The builder is a shared service that accumulates no state: the methods that set a header, the payload or
 * add a recipient return a new object, the key and content encryption algorithms are resolved by build()
 * from the complete header of each recipient and the order of the calls is therefore irrelevant.
 *
 * @internal
 */
final class JWEBuilderImmutabilityTest extends EncryptionTestCase
{
    private const PAYLOAD = 'Live long and prosper.';

    #[Test]
    public function theRecipientCanBeAddedBeforeTheSharedProtectedHeader(): void
    {
        $jwe = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128CBC-HS256'])
            ->withPayload(self::PAYLOAD)
            ->addRecipient($this->getKey())
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128CBC-HS256',
            ])
            ->build();

        static::assertTrue(
            $this->getJWEDecrypterFactory()
                ->create(['A128KW', 'A128CBC-HS256'])
                ->decryptUsingKey($jwe, $this->getKey(), 0)
        );
        static::assertSame(self::PAYLOAD, $jwe->getPayload());
    }

    #[Test]
    public function theAccumulationMethodsDoNotModifyTheReceiver(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128CBC-HS256']);

        $jweBuilder->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128CBC-HS256',
                'cty' => 'text/plain',
            ])
            ->withAAD('foo')
            ->addRecipient($this->getKey());

        $jwe = $jweBuilder->withPayload('Another payload.')
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128CBC-HS256',
            ])
            ->addRecipient($this->getKey())
            ->build();

        static::assertCount(1, $jwe->getRecipients());
        static::assertNull($jwe->getAAD());
        static::assertFalse($jwe->hasSharedProtectedHeaderParameter('cty'));
        static::assertTrue(
            $this->getJWEDecrypterFactory()
                ->create(['A128KW', 'A128CBC-HS256'])
                ->decryptUsingKey($jwe, $this->getKey(), 0)
        );
        static::assertSame('Another payload.', $jwe->getPayload());
    }

    #[Test]
    public function theCreateMethodIsDeprecatedAndReturnsAPristineBuilder(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128CBC-HS256'])
            ->withPayload(self::PAYLOAD);

        $reset = null;
        $deprecations = $this->collectDeprecations(static function () use ($jweBuilder, &$reset): void {
            $reset = $jweBuilder->create();
        });

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'The method "Jose\Component\Encryption\JWEBuilder::create()" is deprecated and will be removed in 5.0.0.',
            $deprecations[0]
        );
        static::assertInstanceOf(JWEBuilder::class, $reset);
        static::assertNotSame($jweBuilder, $reset);
    }

    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
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
