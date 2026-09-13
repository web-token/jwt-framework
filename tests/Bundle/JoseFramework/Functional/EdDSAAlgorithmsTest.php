<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\Ed25519;
use Jose\Component\Signature\Algorithm\Ed448;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;
use function in_array;

/**
 * The Edwards-curve signature algorithms are registered when the platform can run them: "Ed25519" and the deprecated
 * "EdDSA" with sodium or OpenSSL on PHP 8.4, "Ed448" with OpenSSL on PHP 8.4 only.
 *
 * @internal
 */
final class EdDSAAlgorithmsTest extends WebTestCase
{
    #[Test]
    public function theEd25519AlgorithmsAreRegisteredWhenSupported(): void
    {
        $factory = $this->getAlgorithmManagerFactory();

        static::assertSame(Ed25519::isSupported(), in_array('Ed25519', $factory->aliases(), true));
        static::assertSame(Ed25519::isSupported(), in_array('EdDSA', $factory->aliases(), true));
        if (Ed25519::isSupported()) {
            static::assertInstanceOf(Ed25519::class, $factory->create(['Ed25519'])->get('Ed25519'));
            static::assertInstanceOf(EdDSA::class, $factory->create(['EdDSA'])->get('EdDSA'));
        }
    }

    #[Test]
    public function theEd448AlgorithmIsRegisteredWhenSupported(): void
    {
        $factory = $this->getAlgorithmManagerFactory();

        static::assertSame(Ed448::isSupported(), in_array('Ed448', $factory->aliases(), true));
        if (Ed448::isSupported()) {
            static::assertInstanceOf(Ed448::class, $factory->create(['Ed448'])->get('Ed448'));
        }
    }

    #[Test]
    public function theKeyAnalyzerKnowsTheOctetKeyPairs(): void
    {
        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();
        $analyzer = $container->get(KeyAnalyzerManager::class);
        static::assertInstanceOf(KeyAnalyzerManager::class, $analyzer);
        $key = (new JWKFactory())->okp('Ed25519', [
            'alg' => 'EdDSA',
            'use' => 'sig',
            'kid' => 'key-1',
        ]);

        $messages = array_map(static fn ($message): string => $message->getMessage(), $analyzer->analyze($key)->all());

        static::assertContains(
            'The algorithm "EdDSA" is deprecated (RFC 9864). Use the fully-specified "Ed25519" algorithm instead.',
            $messages
        );
    }

    private function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();
        $factory = $container->get(AlgorithmManagerFactory::class);
        static::assertInstanceOf(AlgorithmManagerFactory::class, $factory);

        return $factory;
    }
}
