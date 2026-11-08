<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Exception;
use InvalidArgumentException;
use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
final class SignatureLimitTest extends SignatureTestCase
{
    #[Test]
    public function aTokenWithMoreSignaturesThanTheLimitIsRejectedBeforeAnySignatureIsProcessed(): void
    {
        $checker = new class() implements HeaderChecker {
            public int $calls = 0;

            public function checkHeader(mixed $value): void
            {
                ++$this->calls;
            }

            public function supportedHeader(): string
            {
                return 'alg';
            }

            public function protectedHeaderOnly(): bool
            {
                return false;
            }
        };
        $jwsLoader = $this->createJWSLoader(10, $checker);
        $key = $this->createKey();

        $this->assertRejected($jwsLoader, $this->createTokenWithForgedSignatures(11), $key);
        static::assertSame(0, $checker->calls);

        $this->assertRejected($jwsLoader, $this->createTokenWithForgedSignatures(10), $key);
        static::assertSame(10, $checker->calls);
    }

    #[Test]
    public function aTokenWithAsManySignaturesAsTheLimitIsVerified(): void
    {
        $keys = $this->createKeys(10);

        $jws = $this->createJWSLoader(10)
            ->loadAndVerifyWithKey($this->createToken($keys), $keys[9], $signature);

        static::assertSame(9, $signature);
        static::assertSame('Live long and prosper.', $jws->getPayload());
    }

    #[Test]
    public function withoutALimitEverySignatureIsTried(): void
    {
        $keys = $this->createKeys(11);

        $jws = $this->createJWSLoader(null)
            ->loadAndVerifyWithKey($this->createToken($keys), $keys[10], $signature);

        static::assertSame(10, $signature);
        static::assertSame('Live long and prosper.', $jws->getPayload());
    }

    #[DataProvider('dataInvalidLimits')]
    #[Test]
    public function anInvalidLimitIsRefused(mixed $limit): void
    {
        $loader = $this->getJWSLoaderFactory()
            ->create(['jws_json_general'], ['HS256']);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The maximum number of signatures must be a positive integer.');

        new JWSLoader($loader->getSerializerManager(), $loader->getJwsVerifier(), null, $limit);
    }

    public static function dataInvalidLimits(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
        yield 'string' => ['10'];
    }

    private function createJWSLoader(?int $maxSignatures, ?HeaderChecker $checker = null): JWSLoader
    {
        $jwsLoader = $this->getJWSLoaderFactory()
            ->create(['jws_json_general'], ['HS256']);

        return new JWSLoader(
            $jwsLoader->getSerializerManager(),
            $jwsLoader->getJwsVerifier(),
            $checker === null ? null : new HeaderCheckerManager([$checker], [new JWSTokenSupport()]),
            $maxSignatures
        );
    }

    private function createTokenWithForgedSignatures(int $count): string
    {
        return JsonConverter::encode([
            'payload' => Base64UrlSafe::encodeUnpadded('Live long and prosper.'),
            'signatures' => array_fill(0, $count, [
                'protected' => Base64UrlSafe::encodeUnpadded(JsonConverter::encode([
                    'alg' => 'HS256',
                ])),
                'signature' => 'AA',
            ]),
        ]);
    }

    /**
     * @param JWK[] $keys
     */
    private function createToken(array $keys): string
    {
        $jwsBuilder = $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->create()
            ->withPayload('Live long and prosper.');
        foreach ($keys as $key) {
            $jwsBuilder = $jwsBuilder->addSignature($key, [
                'alg' => 'HS256',
            ]);
        }

        return $this->getJWSSerializerManager()
            ->serialize('jws_json_general', $jwsBuilder->build());
    }

    /**
     * @return JWK[]
     */
    private function createKeys(int $count): array
    {
        $keys = [];
        for ($i = 0; $i < $count; ++$i) {
            $keys[] = $this->createKey();
        }

        return $keys;
    }

    private function createKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);
    }

    private function assertRejected(JWSLoader $jwsLoader, string $token, JWK $key): void
    {
        try {
            $jwsLoader->loadAndVerifyWithKey($token, $key, $signature);
        } catch (Exception $exception) {
            static::assertSame('Unable to load and verify the token.', $exception->getMessage());

            return;
        }
        static::fail('The token has been verified.');
    }
}
