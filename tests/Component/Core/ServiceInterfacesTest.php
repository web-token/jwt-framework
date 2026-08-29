<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimCheckerManagerInterface;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEBuilderInterface;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWEDecrypterInterface;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWELoaderInterface;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\NestedToken\NestedTokenBuilder;
use Jose\Component\NestedToken\NestedTokenBuilderInterface;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\NestedToken\NestedTokenLoaderInterface;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSBuilderInterface;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderInterface;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSVerifierInterface;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function is_a;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

/**
 * The services of the library are open only because the bundle used to extend them. They now carry an interface, so
 * that they can be decorated instead, and extending them is deprecated.
 *
 * @internal
 */
final class ServiceInterfacesTest extends TestCase
{
    #[Test]
    #[DataProvider('services')]
    public function theServiceImplementsItsInterface(string $service, string $interface): void
    {
        static::assertTrue(is_a($service, $interface, true));
    }

    #[Test]
    public function extendingAServiceIsDeprecated(): void
    {
        $deprecations = $this->collectDeprecations(static fn (): object => new ExtendedJWSBuilder(
            new AlgorithmManager([])
        ));

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(JWSBuilder::class, $deprecations[0]);
        static::assertStringContainsString(JWSBuilderInterface::class, $deprecations[0]);
    }

    #[Test]
    public function usingAServiceIsNotDeprecated(): void
    {
        $deprecations = $this->collectDeprecations(
            static fn (): object => new JWSBuilder(new AlgorithmManager([]))
        );

        static::assertSame([], $deprecations);
    }

    /**
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function services(): iterable
    {
        yield 'JWS builder' => [JWSBuilder::class, JWSBuilderInterface::class];
        yield 'JWS verifier' => [JWSVerifier::class, JWSVerifierInterface::class];
        yield 'JWS loader' => [JWSLoader::class, JWSLoaderInterface::class];
        yield 'JWE builder' => [JWEBuilder::class, JWEBuilderInterface::class];
        yield 'JWE decrypter' => [JWEDecrypter::class, JWEDecrypterInterface::class];
        yield 'JWE loader' => [JWELoader::class, JWELoaderInterface::class];
        yield 'Nested token builder' => [NestedTokenBuilder::class, NestedTokenBuilderInterface::class];
        yield 'Nested token loader' => [NestedTokenLoader::class, NestedTokenLoaderInterface::class];
        yield 'Claim checker manager' => [ClaimCheckerManager::class, ClaimCheckerManagerInterface::class];
        yield 'Header checker manager' => [HeaderCheckerManager::class, HeaderCheckerManagerInterface::class];
    }

    #[Test]
    public function theLoadersAcceptAnyImplementationOfTheInterfaces(): void
    {
        $jwsLoader = new JWSLoader(
            new JWSSerializerManager([]),
            static::createStub(JWSVerifierInterface::class),
            static::createStub(HeaderCheckerManagerInterface::class)
        );
        $jweLoader = new JWELoader(
            new JWESerializerManager([]),
            static::createStub(JWEDecrypterInterface::class),
            static::createStub(HeaderCheckerManagerInterface::class)
        );

        static::assertInstanceOf(JWSVerifierInterface::class, $jwsLoader->getJwsVerifier());
        static::assertInstanceOf(JWEDecrypterInterface::class, $jweLoader->getJweDecrypter());

        $nestedTokenLoader = new NestedTokenLoader($jweLoader, $jwsLoader);
        $nestedTokenBuilder = new NestedTokenBuilder(
            static::createStub(JWEBuilderInterface::class),
            new JWESerializerManager([]),
            static::createStub(JWSBuilderInterface::class),
            new JWSSerializerManager([])
        );

        static::assertInstanceOf(NestedTokenLoaderInterface::class, $nestedTokenLoader);
        static::assertInstanceOf(NestedTokenBuilderInterface::class, $nestedTokenBuilder);
    }

    /**
     * @param callable(): object $callable
     *
     * @return string[]
     */
    private function collectDeprecations(callable $callable): array
    {
        $deprecations = [];
        set_error_handler(static function (int $type, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callable();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
