<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\DecryptionResult;
use Jose\Component\Encryption\JWE;
use PHPUnit\Framework\Attributes\Test;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

/**
 * The payload of a JWE is only known once a recipient has been decrypted, which is why the decrypter is the only
 * object allowed to set it. Calling the mutator from anywhere else is deprecated, so that the payload exposed by a
 * token remains the one that was authenticated against the ciphertext.
 *
 * @internal
 */
final class SealedJWEMutatorTest extends EncryptionTestCase
{
    private const PAYLOAD = 'Live long and prosper.';

    #[Test]
    public function settingThePayloadFromOutsideTheLibraryIsDeprecated(): void
    {
        $jwe = $this->buildJWE();

        $deprecations = $this->collectDeprecations(static function () use ($jwe): void {
            $jwe->withPayload('Another payload.');
        });

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'The method "Jose\Component\Encryption\JWE::withPayload()" is internal to the library.',
            $deprecations[0]
        );
    }

    #[Test]
    public function theDecrypterSetsThePayloadWithoutDeprecation(): void
    {
        $jwe = $this->buildJWE();

        $result = null;
        $deprecations = $this->collectDeprecations(function () use ($jwe, &$result): void {
            $result = $this->getJWEDecrypterFactory()
                ->create(['A128KW', 'A128CBC-HS256'])
                ->decrypt($jwe, $this->getKey(), 0);
        });

        static::assertSame([], $deprecations);
        static::assertInstanceOf(DecryptionResult::class, $result);
        static::assertTrue($result->isDecrypted());
        static::assertSame(self::PAYLOAD, $result->getJwe()->getPayload());
    }

    private function buildJWE(): JWE
    {
        return $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128CBC-HS256'])
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128CBC-HS256',
            ])
            ->addRecipient($this->getKey())
            ->build();
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
