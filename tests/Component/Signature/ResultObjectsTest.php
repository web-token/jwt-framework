<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
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
final class ResultObjectsTest extends SignatureTestCase
{
    #[Test]
    public function theVerifierReturnsTheKeyThatVerifiedTheSignature(): void
    {
        $jws = $this->createJWS();
        $result = $this->getVerifier()
            ->verify($jws, $this->getKeySet(), 0);

        static::assertTrue($result->isVerified());
        static::assertSame(0, $result->getSignatureIndex());
        static::assertSame($this->getKey()->all(), $result->getKey()?->all());
    }

    #[Test]
    public function theVerifierAcceptsASingleKey(): void
    {
        $jws = $this->createJWS();
        $result = $this->getVerifier()
            ->verify($jws, $this->getKey(), 0);

        static::assertTrue($result->isVerified());
        static::assertSame($this->getKey()->all(), $result->getKey()?->all());
    }

    #[Test]
    public function theVerifierReportsAFailureWithoutAnyKey(): void
    {
        $jws = $this->createJWS();
        $result = $this->getVerifier()
            ->verify($jws, new JWKSet([$this->getWrongKey()]), 0);

        static::assertFalse($result->isVerified());
        static::assertNull($result->getKey());
        static::assertSame(0, $result->getSignatureIndex());
    }

    #[Test]
    public function theVerifierReportsEveryDiscardedFailure(): void
    {
        $jws = $this->createJWS();
        $errors = [];
        $result = $this->getVerifier()
            ->verify($jws, new JWKSet([$this->getWrongKey()]), 0, null, static function (
                Throwable $throwable
            ) use (&$errors): void {
                $errors[] = $throwable->getMessage();
            });

        static::assertFalse($result->isVerified());
        static::assertGreaterThan(0, count($errors));
    }

    #[Test]
    public function theLoaderReturnsTheIndexOfTheVerifiedSignature(): void
    {
        $result = $this->getLoader()
            ->loadAndVerify($this->createToken(), $this->getKeySet());

        static::assertSame('Live long and prosper.', $result->getJws()->getPayload());
        static::assertSame(0, $result->getSignatureIndex());
        static::assertSame($this->getKey()->all(), $result->getKey()->all());
    }

    #[Test]
    public function theLoaderAcceptsASingleKey(): void
    {
        $result = $this->getLoader()
            ->loadAndVerify($this->createToken(), $this->getKey());

        static::assertSame('Live long and prosper.', $result->getJws()->getPayload());
    }

    #[Test]
    public function theSerializerManagerReturnsTheNameOfTheSerializer(): void
    {
        $result = $this->getJWSSerializerManager()
            ->unserializeToken($this->createToken());

        static::assertSame('jws_compact', $result->getSerializerName());
        static::assertSame('Live long and prosper.', $result->getJws()->getPayload());
    }

    #[Test]
    public function theDeprecatedVerifierMethodStillPopulatesTheKey(): void
    {
        $jws = $this->createJWS();
        $jwk = null;
        $verified = false;
        $deprecations = $this->collectDeprecations(function () use ($jws, &$jwk, &$verified): void {
            $verified = $this->getVerifier()
                ->verifyWithKeySet($jws, $this->getKeySet(), 0, null, $jwk);
        });

        static::assertTrue($verified);
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertSame($this->getKey()->all(), $jwk->all());
        static::assertCount(1, $deprecations);
        static::assertStringContainsString('::verifyWithKeySet()" is deprecated', $deprecations[0]);
    }

    #[Test]
    public function theVerificationWithASingleKeyIsNotDeprecated(): void
    {
        $jws = $this->createJWS();
        $verified = false;
        $deprecations = $this->collectDeprecations(function () use ($jws, &$verified): void {
            $verified = $this->getVerifier()
                ->verifyWithKey($jws, $this->getKey(), 0);
        });

        static::assertTrue($verified);
        static::assertSame([], $deprecations);
    }

    #[Test]
    public function theDeprecatedLoaderMethodsStillPopulateTheSignatureIndex(): void
    {
        $token = $this->createToken();
        $withKey = null;
        $withKeySet = null;
        $deprecations = $this->collectDeprecations(function () use ($token, &$withKey, &$withKeySet): void {
            $this->getLoader()
                ->loadAndVerifyWithKey($token, $this->getKey(), $withKey);
            $this->getLoader()
                ->loadAndVerifyWithKeySet($token, $this->getKeySet(), $withKeySet);
        });

        static::assertSame(0, $withKey);
        static::assertSame(0, $withKeySet);
        static::assertCount(3, $deprecations);
        static::assertStringContainsString('::loadAndVerifyWithKey()" is deprecated', $deprecations[0]);
        static::assertStringContainsString('::loadAndVerifyWithKeySet()" is deprecated', $deprecations[1]);
        static::assertStringContainsString('::loadAndVerifyWithKeySet()" is deprecated', $deprecations[2]);
    }

    /**
     * "loadAndVerifyWithKey()" delegated to "loadAndVerifyWithKeySet()" before 4.3.0. It still does, so that an
     * object extending the loader and overriding the key set method keeps intercepting both.
     */
    #[Test]
    public function theDeprecatedKeyMethodStillGoesThroughItsKeySetCounterpart(): void
    {
        $verifier = $this->getJWSVerifierFactory()
            ->create(['HS256']);
        $loader = new class($this->getJWSSerializerManager(), $verifier, null) extends JWSLoader {
            public bool $keySetMethodWasCalled = false;

            #[Override]
            public function loadAndVerifyWithKeySet(
                string $token,
                JWKSet $keyset,
                ?int &$signature,
                ?string $payload = null
            ): JWS {
                $this->keySetMethodWasCalled = true;

                return parent::loadAndVerifyWithKeySet($token, $keyset, $signature, $payload);
            }
        };

        $index = null;
        $loader->loadAndVerifyWithKey($this->createToken(), $this->getKey(), $index);

        static::assertSame(0, $index);
        static::assertTrue($loader->keySetMethodWasCalled);
    }

    #[Test]
    public function onlyThePassedSerializerNameArgumentIsDeprecated(): void
    {
        $token = $this->createToken();
        $name = null;
        $deprecations = $this->collectDeprecations(function () use ($token, &$name): void {
            $this->getJWSSerializerManager()
                ->unserialize($token);
            $this->getJWSSerializerManager()
                ->unserialize($token, $name);
        });

        static::assertSame('jws_compact', $name);
        static::assertCount(1, $deprecations);
        static::assertStringContainsString('Passing the "$name" argument', $deprecations[0]);
    }

    private function getVerifier(): JWSVerifier
    {
        return $this->getJWSVerifierFactory()
            ->create(['HS256']);
    }

    private function getLoader(): JWSLoader
    {
        return $this->getJWSLoaderFactory()
            ->create(['jws_compact'], ['HS256']);
    }

    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);
    }

    private function getWrongKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
        ]);
    }

    private function getKeySet(): JWKSet
    {
        return new JWKSet([$this->getWrongKey(), $this->getKey()]);
    }

    private function createJWS(): JWS
    {
        return $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->create()
            ->withPayload('Live long and prosper.')
            ->addSignature($this->getKey(), [
                'alg' => 'HS256',
            ])
            ->build();
    }

    private function createToken(): string
    {
        return $this->getJWSSerializerManager()
            ->serialize('jws_compact', $this->createJWS(), 0);
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
