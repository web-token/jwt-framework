<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\KeyManagement\JWKFactory;
use Override;
use PHPUnit\Framework\Attributes\Test;
use Throwable;
use function count;
use const E_USER_DEPRECATED;

/**
 * The methods that used to populate variables of the caller are deprecated and replaced with methods that return a
 * result object. The deprecated methods are implemented on top of the new ones and keep their exact behaviour.
 *
 * @internal
 */
final class ResultObjectsTest extends EncryptionTestCase
{
    private ?JWK $key = null;

    private ?JWK $wrongKey = null;

    #[Test]
    public function theDecrypterReturnsTheDecryptedTokenAndTheKey(): void
    {
        $jwe = $this->createJWE();
        $result = $this->getDecrypter()
            ->decrypt($jwe, $this->getKeySet(), 0);

        static::assertTrue($result->isDecrypted());
        static::assertSame(0, $result->getRecipientIndex());
        static::assertSame('Live long and prosper.', $result->getJwe()->getPayload());
        static::assertSame($this->getKey()->all(), $result->getKey()?->all());
    }

    #[Test]
    public function theDecrypterLeavesTheGivenTokenUntouched(): void
    {
        $jwe = $this->createJWE();
        $this->getDecrypter()
            ->decrypt($jwe, $this->getKeySet(), 0);

        static::assertNull($jwe->getPayload());
    }

    #[Test]
    public function theDecrypterAcceptsASingleKey(): void
    {
        $result = $this->getDecrypter()
            ->decrypt($this->createJWE(), $this->getKey(), 0);

        static::assertTrue($result->isDecrypted());
        static::assertSame('Live long and prosper.', $result->getJwe()->getPayload());
    }

    #[Test]
    public function theDecrypterReportsAFailureWithoutAnyKey(): void
    {
        $jwe = $this->createJWE();
        $errors = [];
        $result = $this->getDecrypter()
            ->decrypt($jwe, new JWKSet([$this->getWrongKey()]), 0, null, static function (
                Throwable $throwable
            ) use (&$errors): void {
                $errors[] = $throwable->getMessage();
            });

        static::assertFalse($result->isDecrypted());
        static::assertNull($result->getKey());
        static::assertNull($result->getJwe()->getPayload());
        static::assertGreaterThan(0, count($errors));
    }

    #[Test]
    public function theLoaderReturnsTheIndexOfTheDecryptedRecipient(): void
    {
        $result = $this->getLoader()
            ->loadAndDecrypt($this->createToken(), $this->getKeySet());

        static::assertSame('Live long and prosper.', $result->getJwe()->getPayload());
        static::assertSame(0, $result->getRecipientIndex());
        static::assertSame($this->getKey()->all(), $result->getKey()?->all());
    }

    #[Test]
    public function theLoaderAcceptsASingleKey(): void
    {
        $result = $this->getLoader()
            ->loadAndDecrypt($this->createToken(), $this->getKey());

        static::assertSame('Live long and prosper.', $result->getJwe()->getPayload());
    }

    #[Test]
    public function theSerializerManagerReturnsTheNameOfTheSerializer(): void
    {
        $result = $this->getJWESerializerManager()
            ->unserializeToken($this->createToken());

        static::assertSame('jwe_compact', $result->getSerializerName());
        static::assertSame(1, $result->getJwe()->countRecipients());
    }

    #[Test]
    public function theDeprecatedDecrypterMethodsStillReplaceTheGivenToken(): void
    {
        $withKey = $this->createJWE();
        $withKeySet = $this->createJWE();
        $jwk = null;
        $deprecations = $this->collectDeprecations(function () use (&$withKey, &$withKeySet, &$jwk): void {
            static::assertTrue($this->getDecrypter()->decryptUsingKey($withKey, $this->getKey(), 0));
            static::assertTrue(
                $this->getDecrypter()
                    ->decryptUsingKeySet($withKeySet, $this->getKeySet(), 0, $jwk)
            );
        });

        static::assertSame('Live long and prosper.', $withKey->getPayload());
        static::assertSame('Live long and prosper.', $withKeySet->getPayload());
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertSame($this->getKey()->all(), $jwk->all());
        static::assertCount(3, $deprecations);
        static::assertStringContainsString('::decryptUsingKey()" is deprecated', $deprecations[0]);
        static::assertStringContainsString('::decryptUsingKeySet()" is deprecated', $deprecations[1]);
        static::assertStringContainsString('::decryptUsingKeySet()" is deprecated', $deprecations[2]);
    }

    /**
     * "decryptUsingKey()" delegated to "decryptUsingKeySet()" before 4.3.0. It still does, so that an object
     * extending the decrypter and overriding the key set method keeps intercepting both.
     */
    #[Test]
    public function theDeprecatedKeyMethodStillGoesThroughItsKeySetCounterpart(): void
    {
        $algorithmManager = $this->getAlgorithmManagerFactory()
            ->create(['A256KW', 'A256GCM']);
        $decrypter = new class($algorithmManager) extends JWEDecrypter {
            public bool $keySetMethodWasCalled = false;

            #[Override]
            public function decryptUsingKeySet(
                JWE &$jwe,
                JWKSet $jwkset,
                int $recipient,
                ?JWK &$jwk = null,
                ?JWK $senderKey = null
            ): bool {
                $this->keySetMethodWasCalled = true;

                return parent::decryptUsingKeySet($jwe, $jwkset, $recipient, $jwk, $senderKey);
            }
        };

        $jwe = $this->createJWE();
        static::assertTrue($decrypter->decryptUsingKey($jwe, $this->getKey(), 0));
        static::assertTrue($decrypter->keySetMethodWasCalled);
    }

    #[Test]
    public function theDeprecatedLoaderMethodsStillPopulateTheRecipientIndex(): void
    {
        $token = $this->createToken();
        $withKey = null;
        $withKeySet = null;
        $deprecations = $this->collectDeprecations(function () use ($token, &$withKey, &$withKeySet): void {
            $this->getLoader()
                ->loadAndDecryptWithKey($token, $this->getKey(), $withKey);
            $this->getLoader()
                ->loadAndDecryptWithKeySet($token, $this->getKeySet(), $withKeySet);
        });

        static::assertSame(0, $withKey);
        static::assertSame(0, $withKeySet);
        static::assertCount(3, $deprecations);
        static::assertStringContainsString('::loadAndDecryptWithKey()" is deprecated', $deprecations[0]);
        static::assertStringContainsString('::loadAndDecryptWithKeySet()" is deprecated', $deprecations[1]);
        static::assertStringContainsString('::loadAndDecryptWithKeySet()" is deprecated', $deprecations[2]);
    }

    #[Test]
    public function onlyThePassedSerializerNameArgumentIsDeprecated(): void
    {
        $token = $this->createToken();
        $name = null;
        $deprecations = $this->collectDeprecations(function () use ($token, &$name): void {
            $this->getJWESerializerManager()
                ->unserialize($token);
            $this->getJWESerializerManager()
                ->unserialize($token, $name);
        });

        static::assertSame('jwe_compact', $name);
        static::assertCount(1, $deprecations);
        static::assertStringContainsString('Passing the "$name" argument', $deprecations[0]);
    }

    private function getDecrypter(): JWEDecrypter
    {
        return $this->getJWEDecrypterFactory()
            ->create(['A256KW', 'A256GCM']);
    }

    private function getLoader(): JWELoader
    {
        return $this->getJWELoaderFactory()
            ->create(['jwe_compact'], ['A256KW', 'A256GCM']);
    }

    private function getKey(): JWK
    {
        if ($this->key === null) {
            $this->key = (new JWKFactory())->oct(256, [
                'alg' => 'A256KW',
                'use' => 'enc',
            ]);
        }

        return $this->key;
    }

    private function getWrongKey(): JWK
    {
        if ($this->wrongKey === null) {
            $this->wrongKey = (new JWKFactory())->oct(256, [
                'alg' => 'A256KW',
                'use' => 'enc',
            ]);
        }

        return $this->wrongKey;
    }

    private function getKeySet(): JWKSet
    {
        return new JWKSet([$this->getWrongKey(), $this->getKey()]);
    }

    private function createJWE(): JWE
    {
        return $this->getJWEBuilderFactory()
            ->create(['A256KW', 'A256GCM'])
            ->create()
            ->withPayload('Live long and prosper.')
            ->withSharedProtectedHeader([
                'alg' => 'A256KW',
                'enc' => 'A256GCM',
            ])
            ->addRecipient($this->getKey())
            ->build();
    }

    private function createToken(): string
    {
        return $this->getJWESerializerManager()
            ->serialize('jwe_compact', $this->createJWE(), 0);
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
