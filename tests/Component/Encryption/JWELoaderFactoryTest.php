<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Checker\IsEqualChecker;
use Jose\Component\Encryption\JWELoaderFactory;
use Jose\Component\Encryption\JWETokenSupport;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
final class JWELoaderFactoryTest extends EncryptionTestCase
{
    #[Test]
    public function headerCheckersAreRefusedWithoutAHeaderCheckerManagerFactory(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Header checkers were requested, but no header checker manager factory is available.'
        );

        $this->getJWELoaderFactory()
            ->create(['jwe_compact'], ['A256KW', 'A256GCM'], ['typ']);
    }

    #[Test]
    public function aLoaderWithoutHeaderCheckersNeedsNoHeaderCheckerManagerFactory(): void
    {
        $loader = $this->getJWELoaderFactory()
            ->create(['jwe_compact'], ['A256KW', 'A256GCM']);

        static::assertNull($loader->getHeaderCheckerManager());
    }

    #[Test]
    public function theRequestedHeaderCheckersAreGivenToTheLoader(): void
    {
        $checker = new IsEqualChecker('typ', 'at+jwt');
        $headerCheckerManagerFactory = new HeaderCheckerManagerFactory();
        $headerCheckerManagerFactory->add('typ', $checker);
        $headerCheckerManagerFactory->addTokenTypeSupport(new JWETokenSupport());
        $factory = new JWELoaderFactory(
            $this->getJWESerializerManagerFactory(),
            $this->getJWEDecrypterFactory(),
            $headerCheckerManagerFactory
        );

        $loader = $factory->create(['jwe_compact'], ['A256KW', 'A256GCM'], ['typ']);

        static::assertSame([
            'typ' => $checker,
        ], $loader->getHeaderCheckerManager()?->getCheckers());
    }
}
