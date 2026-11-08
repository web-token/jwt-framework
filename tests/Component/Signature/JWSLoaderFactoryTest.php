<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use InvalidArgumentException;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Checker\IsEqualChecker;
use Jose\Component\Signature\JWSLoaderFactory;
use Jose\Component\Signature\JWSTokenSupport;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
final class JWSLoaderFactoryTest extends SignatureTestCase
{
    #[Test]
    public function headerCheckersAreRefusedWithoutAHeaderCheckerManagerFactory(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Header checkers were requested, but no header checker manager factory is available.'
        );

        $this->getJWSLoaderFactory()
            ->create(['jws_compact'], ['HS256'], ['typ']);
    }

    #[Test]
    public function aLoaderWithoutHeaderCheckersNeedsNoHeaderCheckerManagerFactory(): void
    {
        $loader = $this->getJWSLoaderFactory()
            ->create(['jws_compact'], ['HS256']);

        static::assertNull($loader->getHeaderCheckerManager());
    }

    #[Test]
    public function theRequestedHeaderCheckersAreGivenToTheLoader(): void
    {
        $checker = new IsEqualChecker('typ', 'at+jwt');
        $headerCheckerManagerFactory = new HeaderCheckerManagerFactory();
        $headerCheckerManagerFactory->add('typ', $checker);
        $headerCheckerManagerFactory->addTokenTypeSupport(new JWSTokenSupport());
        $factory = new JWSLoaderFactory(
            $this->getJWSSerializerManagerFactory(),
            $this->getJWSVerifierFactory(),
            $headerCheckerManagerFactory
        );

        $loader = $factory->create(['jws_compact'], ['HS256'], ['typ']);

        static::assertSame([
            'typ' => $checker,
        ], $loader->getHeaderCheckerManager()?->getCheckers());
    }
}
