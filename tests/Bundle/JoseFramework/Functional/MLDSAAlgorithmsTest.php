<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\Signature\Algorithm\MLDSA44;
use Jose\Component\Signature\Algorithm\MLDSA65;
use Jose\Component\Signature\Algorithm\MLDSA87;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;
use function in_array;

/**
 * The ML-DSA algorithms are registered when the platform can run them (PHP 8.4 and an OpenSSL runtime providing
 * ML-DSA); the container compiles either way.
 *
 * @internal
 */
final class MLDSAAlgorithmsTest extends WebTestCase
{
    #[Test]
    public function theAlgorithmsAreRegisteredWhenSupported(): void
    {
        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();
        $factory = $container->get(AlgorithmManagerFactory::class);
        static::assertInstanceOf(AlgorithmManagerFactory::class, $factory);

        foreach ([
            'ML-DSA-44' => MLDSA44::class,
            'ML-DSA-65' => MLDSA65::class,
            'ML-DSA-87' => MLDSA87::class,
        ] as $alias => $class) {
            static::assertSame(MLDSA44::isSupported(), in_array($alias, $factory->aliases(), true));
            if (MLDSA44::isSupported()) {
                static::assertInstanceOf($class, $factory->create([$alias])->get($alias));
            }
        }
    }

    #[Test]
    public function theKeyAnalyzerKnowsTheAkpKeys(): void
    {
        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();
        $analyzer = $container->get(KeyAnalyzerManager::class);
        static::assertInstanceOf(KeyAnalyzerManager::class, $analyzer);
        $key = new JWK([
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'use' => 'sig',
            'kid' => 'key-1',
            'pub' => 'AAAA',
        ]);

        $messages = array_map(static fn ($message): string => $message->getMessage(), $analyzer->analyze($key)->all());

        static::assertContains('Invalid key. The parameter "pub" of an ML-DSA-44 key shall be 1312 bytes.', $messages);
    }
}
