<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core\Util;

use Brick\Math\Internal\Calculator;
use Brick\Math\Internal\Calculator\NativeCalculator;
use Brick\Math\Internal\CalculatorRegistry;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;
use const OPENSSL_KEYTYPE_RSA;

/**
 * @internal
 */
final class RSAKeyTest extends TestCase
{
    protected function tearDown(): void
    {
        self::useCalculator(null);
    }

    #[Test]
    public function theLimitsOfOpenSSLAreAccepted(): void
    {
        static::assertSame(2048, RSAKey::createFromJWK(self::key(2048, 8))->getModulusLength());
        static::assertSame(385, RSAKey::createFromJWK(self::key(385, 8))->getModulusLength());
        static::assertSame(384, RSAKey::createFromJWK(self::key(384, 384))->getModulusLength());
        static::assertSame(256, RSAKey::createFromJWK(self::key(256, 9))->getModulusLength());
    }

    #[Test]
    #[DataProvider('oversizedKeys')]
    public function aKeyBeyondTheLimitsOfOpenSSLIsRejected(
        int $modulusLength,
        int $exponentLength,
        string $member
    ): void {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The key parameter "%s" is too long.', $member));

        RSAKey::createFromJWK(self::key($modulusLength, $exponentLength));
    }

    /**
     * @return iterable<string, array{int, int, string}>
     */
    public static function oversizedKeys(): iterable
    {
        yield 'modulus of 16392 bits' => [2049, 3, 'n'];
        yield 'exponent of 72 bits, modulus of 16384 bits' => [2048, 9, 'e'];
        yield 'exponent of 72 bits, modulus of 3080 bits' => [385, 9, 'e'];
        yield 'exponent longer than a modulus of 3072 bits' => [384, 385, 'e'];
        yield 'exponent longer than a modulus of 2048 bits' => [256, 257, 'e'];
    }

    #[Test]
    public function leadingZeroBytesAreNotCounted(): void
    {
        $key = self::key(2048, 8);
        $padded = new JWK([
            'kty' => 'RSA',
            'n' => Base64UrlSafe::encodeUnpadded("\0" . Base64UrlSafe::decodeNoPadding($key->get('n'))),
            'e' => Base64UrlSafe::encodeUnpadded(str_repeat("\0", 8) . Base64UrlSafe::decodeNoPadding($key->get('e'))),
        ]);

        static::assertSame(2048, RSAKey::createFromJWK($padded)->getModulusLength());
        static::assertSame(RSAKey::createFromJWK($key)->toPEM(), RSAKey::createFromJWK($padded)->toPEM());
    }

    /**
     * @param callable(JWK): mixed $operation
     */
    #[Test]
    #[DataProvider('operations')]
    public function everyAlgorithmRejectsTheKeyBeforeComputingWithIt(callable $operation): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key parameter "e" is too long.');

        $operation(self::key(2048, 2048));
    }

    /**
     * @return iterable<string, array{callable(JWK): mixed}>
     */
    public static function operations(): iterable
    {
        yield 'RS256' => [
            static fn (JWK $key): bool => (new RS256())->verify($key, 'input', str_repeat("\1", 2048)),
        ];
        yield 'PS256' => [
            static fn (JWK $key): bool => (new PS256())->verify($key, 'input', str_repeat("\1", 2048)),
        ];
        yield 'RSA-OAEP-256' => [
            static function (JWK $key): string {
                $additionalHeader = [];

                return (new RSAOAEP256())->encryptKey($key, str_repeat("\1", 32), [], $additionalHeader);
            },
        ];
    }

    #[Test]
    public function theRsaPkcs1AlgorithmsDoNotConvertTheKeyIntoBigIntegers(): void
    {
        [$key] = self::generateKey(4096);
        self::useCalculator(new NativeCalculator());
        $start = self::cpuTime();

        $signature = (new RS256())->sign($key, 'input');
        $verified = (new RS256())->verify($key->toPublic(), 'input', $signature);

        static::assertTrue($verified);
        static::assertLessThan(1, self::cpuTime() - $start);
    }

    #[Test]
    public function thePemHoldsTheMembersOfTheKey(): void
    {
        [$key, $members] = self::generateKey(2048);

        $private = openssl_pkey_get_private(RSAKey::createFromJWK($key)->toPEM());
        $public = openssl_pkey_get_public(RSAKey::createFromJWK($key->toPublic())->toPEM());

        static::assertNotFalse($private);
        static::assertNotFalse($public);
        static::assertSame($members, openssl_pkey_get_details($private)['rsa'] ?? null);
        static::assertSame([
            'n' => $members['n'],
            'e' => $members['e'],
        ], openssl_pkey_get_details($public)['rsa'] ?? null);
    }

    private static function key(int $modulusLength, int $exponentLength): JWK
    {
        return new JWK([
            'kty' => 'RSA',
            'n' => Base64UrlSafe::encodeUnpadded(str_repeat("\xFF", $modulusLength)),
            'e' => Base64UrlSafe::encodeUnpadded(str_repeat("\xFF", $exponentLength)),
        ]);
    }

    /**
     * @return array{JWK, array<string, string>}
     */
    private static function generateKey(int $bits): array
    {
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $bits,
        ]);
        static::assertNotFalse($resource);
        $details = openssl_pkey_get_details($resource);
        static::assertIsArray($details);
        $values = [
            'kty' => 'RSA',
        ];
        foreach ([
            'n' => 'n',
            'e' => 'e',
            'd' => 'd',
            'p' => 'p',
            'q' => 'q',
            'dp' => 'dmp1',
            'dq' => 'dmq1',
            'qi' => 'iqmp',
        ] as $member => $name) {
            $values[$member] = Base64UrlSafe::encodeUnpadded($details['rsa'][$name]);
        }

        return [new JWK($values), $details['rsa']];
    }

    private static function useCalculator(?Calculator $calculator): void
    {
        if (class_exists(CalculatorRegistry::class)) {
            CalculatorRegistry::set($calculator);

            return;
        }
        Calculator::set($calculator);
    }

    private static function cpuTime(): float
    {
        $usage = getrusage();
        $seconds = $usage['ru_utime.tv_sec'] + $usage['ru_stime.tv_sec'];

        return $seconds + ($usage['ru_utime.tv_usec'] + $usage['ru_stime.tv_usec']) / 1e6;
    }
}
