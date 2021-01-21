<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Easy;

use BadFunctionCallException;
use function get_class;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption;
use Jose\Component\Signature\Algorithm;
use Jose\Easy\AlgorithmProvider;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\ExpectationFailedException;
use PHPUnit\Framework\TestCase;

/**
 * @group  easy
 *
 * @internal
 * @covers \Jose\Easy\AlgorithmProvider
 */
final class AlgorithmProviderTest extends TestCase
{
    private const ALL_ALGORITHMS = [
        Algorithm\HS256::class,
        Algorithm\HS384::class,
        Algorithm\HS512::class,
        Algorithm\RS256::class,
        Algorithm\RS384::class,
        Algorithm\RS512::class,
        Algorithm\PS256::class,
        Algorithm\PS384::class,
        Algorithm\PS512::class,
        Algorithm\ES256::class,
        Algorithm\ES384::class,
        Algorithm\ES512::class,
        Algorithm\EdDSA::class,
        KeyEncryption\A128GCMKW::class,
        KeyEncryption\A192GCMKW::class,
        KeyEncryption\A256GCMKW::class,
        KeyEncryption\A128KW::class,
        KeyEncryption\A192KW::class,
        KeyEncryption\A256KW::class,
        KeyEncryption\Dir::class,
        KeyEncryption\ECDHES::class,
        KeyEncryption\ECDHESA128KW::class,
        KeyEncryption\ECDHESA192KW::class,
        KeyEncryption\ECDHESA256KW::class,
        KeyEncryption\PBES2HS256A128KW::class,
        KeyEncryption\PBES2HS384A192KW::class,
        KeyEncryption\PBES2HS512A256KW::class,
        KeyEncryption\RSA15::class,
        KeyEncryption\RSAOAEP::class,
        KeyEncryption\RSAOAEP256::class,
        ContentEncryption\A128GCM::class,
        ContentEncryption\A192GCM::class,
        ContentEncryption\A256GCM::class,
        ContentEncryption\A128CBCHS256::class,
        ContentEncryption\A192CBCHS384::class,
        ContentEncryption\A256CBCHS512::class,
    ];

    /**
     * @test
     *
     * @throws ExpectationFailedException
     */
    public function itReturnsAllAlgorithmClasses(): void
    {
        $algorithmProvider = new AlgorithmProvider(self::ALL_ALGORITHMS);
        static::assertSame(self::ALL_ALGORITHMS, $algorithmProvider->getAlgorithmClasses());
    }

    /**
     * @test
     *
     * @throws Exception
     * @throws ExpectationFailedException
     */
    public function itReturnsTheAvailableAlgorithms(): void
    {
        $algorithmProvider = new AlgorithmProvider(self::ALL_ALGORITHMS);
        foreach ($algorithmProvider->getAvailableAlgorithms() as $algorithm) {
            static::assertContains(get_class($algorithm), self::ALL_ALGORITHMS);
        }
    }

    /**
     * @test
     *
     * @throws ExpectationFailedException
     * @throws \Exception
     */
    public function itAllowsNonExistingClasses(): void
    {
        $nonExistingClassName = 'NonExistingClass'.bin2hex(random_bytes(31));
        $algorithmProvider = new AlgorithmProvider([$nonExistingClassName]);

        static::assertSame([$nonExistingClassName], $algorithmProvider->getAlgorithmClasses());
        static::assertSame([], $algorithmProvider->getAvailableAlgorithms());
    }

    /**
     * @test
     *
     * @throws ExpectationFailedException
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
        $mockClass = new class() implements Algorithm\SignatureAlgorithm {
            /** @var bool */
            private static $throw;

            public function __construct()
            {
                if (null === self::$throw) {
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

        return get_class($mockClass);
    }
}
