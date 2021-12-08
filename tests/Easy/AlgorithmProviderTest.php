<?php

declare(strict_types=1);

namespace Jose\Tests\Easy;

use BadFunctionCallException;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS384A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Easy\AlgorithmProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class AlgorithmProviderTest extends TestCase
{
    private const ALL_ALGORITHMS = [
        HS256::class,
        HS384::class,
        HS512::class,
        RS256::class,
        RS384::class,
        RS512::class,
        PS256::class,
        PS384::class,
        PS512::class,
        ES256::class,
        ES384::class,
        ES512::class,
        EdDSA::class,
        A128GCMKW::class,
        A192GCMKW::class,
        A256GCMKW::class,
        A128KW::class,
        A192KW::class,
        A256KW::class,
        Dir::class,
        ECDHES::class,
        ECDHESA128KW::class,
        ECDHESA192KW::class,
        ECDHESA256KW::class,
        PBES2HS256A128KW::class,
        PBES2HS384A192KW::class,
        PBES2HS512A256KW::class,
        RSA15::class,
        RSAOAEP::class,
        RSAOAEP256::class,
        A128GCM::class,
        A192GCM::class,
        A256GCM::class,
        A128CBCHS256::class,
        A192CBCHS384::class,
        A256CBCHS512::class,
    ];

    /**
     * @test
     */
    public function itReturnsAllAlgorithmClasses(): void
    {
        $algorithmProvider = new AlgorithmProvider(self::ALL_ALGORITHMS);
        static::assertSame(self::ALL_ALGORITHMS, $algorithmProvider->getAlgorithmClasses());
    }

    /**
     * @test
     */
    public function itReturnsTheAvailableAlgorithms(): void
    {
        $algorithmProvider = new AlgorithmProvider(self::ALL_ALGORITHMS);
        foreach ($algorithmProvider->getAvailableAlgorithms() as $algorithm) {
            static::assertContains($algorithm::class, self::ALL_ALGORITHMS);
        }
    }

    /**
     * @test
     */
    public function itAllowsNonExistingClasses(): void
    {
        $nonExistingClassName = 'NonExistingClass' . bin2hex(random_bytes(31));
        $algorithmProvider = new AlgorithmProvider([$nonExistingClassName]);

        static::assertSame([$nonExistingClassName], $algorithmProvider->getAlgorithmClasses());
        static::assertSame([], $algorithmProvider->getAvailableAlgorithms());
    }

    /**
     * @test
     */
    public function itCanHandleClassesWithExceptions(): void
    {
        $test = [$this->createAlgorithmClassWithExceptionMock()];
        $algorithmProvider = new AlgorithmProvider($test);

        static::assertSame($test, $algorithmProvider->getAlgorithmClasses());
        static::assertSame([], $algorithmProvider->getAvailableAlgorithms());
    }

    private function createAlgorithmClassWithExceptionMock(): string
    {
        $mockClass = new class() implements SignatureAlgorithm {
            private static ?bool $throw = null;

            public function __construct()
            {
                if (self::$throw === null) {
                    self::$throw = true;

                    return;
                }

                throw new BadFunctionCallException('should not be called');
            }

            public function name(): string
            {
                throw new BadFunctionCallException('should not be called');
            }

            public function allowedKeyTypes(): array
            {
                throw new BadFunctionCallException('should not be called');
            }

            public function sign(JWK $key, string $input): string
            {
                throw new BadFunctionCallException('should not be called');
            }

            public function verify(JWK $key, string $input, string $signature): bool
            {
                throw new BadFunctionCallException('should not be called');
            }
        };

        return $mockClass::class;
    }
}
