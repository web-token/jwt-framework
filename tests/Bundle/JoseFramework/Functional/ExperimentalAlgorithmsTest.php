<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Experimental\ContentEncryption\A128CCM_16_128;
use Jose\Experimental\ContentEncryption\A128CCM_16_64;
use Jose\Experimental\ContentEncryption\A128CCM_64_128;
use Jose\Experimental\ContentEncryption\A128CCM_64_64;
use Jose\Experimental\ContentEncryption\A256CCM_16_128;
use Jose\Experimental\ContentEncryption\A256CCM_16_64;
use Jose\Experimental\ContentEncryption\A256CCM_64_128;
use Jose\Experimental\ContentEncryption\A256CCM_64_64;
use Jose\Experimental\KeyEncryption\A128CTR;
use Jose\Experimental\Signature\ES256K;
use Jose\Experimental\Signature\HS1;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function extension_loaded;

/**
 * The algorithms of the jose-experimental package are registered by their own configuration files. Those files used to
 * reference the classes by their pre-4.0 names, so they were never loaded and none of these algorithms was available.
 *
 * @internal
 */
final class ExperimentalAlgorithmsTest extends WebTestCase
{
    #[Test]
    #[DataProvider('aliases')]
    public function theExperimentalAlgorithmIsRegistered(string $alias): void
    {
        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();

        /** @var AlgorithmManagerFactory $factory */
        $factory = $container->get(AlgorithmManagerFactory::class);

        static::assertContains($alias, $factory->aliases());
        static::assertSame($alias, $factory->create([$alias])->get($alias)->name());
    }

    #[Test]
    public function theExperimentalClassesAreTheOnesOfTheExperimentalPackage(): void
    {
        static::assertTrue(class_exists(HS1::class));
        static::assertTrue(class_exists(ES256K::class));
        static::assertTrue(class_exists(A128CTR::class));
        static::assertTrue(class_exists(A128CCM_16_128::class));
    }

    /**
     * Two of them reported the name of another one, so they replaced it in the manager and were unreachable.
     */
    #[Test]
    #[DataProvider('contentEncryptionAlgorithms')]
    public function everyCcmAlgorithmReportsItsOwnName(ContentEncryptionAlgorithm $algorithm, string $name): void
    {
        static::assertSame($name, $algorithm->name());
    }

    /**
     * @return iterable<string, array{ContentEncryptionAlgorithm, string}>
     */
    public static function contentEncryptionAlgorithms(): iterable
    {
        yield 'A128CCM-16-64' => [new A128CCM_16_64(), 'A128CCM-16-64'];
        yield 'A128CCM-16-128' => [new A128CCM_16_128(), 'A128CCM-16-128'];
        yield 'A128CCM-64-64' => [new A128CCM_64_64(), 'A128CCM-64-64'];
        yield 'A128CCM-64-128' => [new A128CCM_64_128(), 'A128CCM-64-128'];
        yield 'A256CCM-16-64' => [new A256CCM_16_64(), 'A256CCM-16-64'];
        yield 'A256CCM-16-128' => [new A256CCM_16_128(), 'A256CCM-16-128'];
        yield 'A256CCM-64-64' => [new A256CCM_64_64(), 'A256CCM-64-64'];
        yield 'A256CCM-64-128' => [new A256CCM_64_128(), 'A256CCM-64-128'];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function aliases(): iterable
    {
        yield 'RS1' => ['RS1'];
        yield 'HS1' => ['HS1'];
        yield 'HS256/64' => ['HS256/64'];
        yield 'ES256K' => ['ES256K'];
        yield 'BLAKE2B' => ['BLAKE2B'];
        yield 'A128CTR' => ['A128CTR'];
        yield 'A192CTR' => ['A192CTR'];
        yield 'A256CTR' => ['A256CTR'];
        yield 'RSA-OAEP-384' => ['RSA-OAEP-384'];
        yield 'RSA-OAEP-512' => ['RSA-OAEP-512'];
        yield 'A128CCM-16-128' => ['A128CCM-16-128'];
        yield 'A256CCM-64-64' => ['A256CCM-64-64'];

        if (extension_loaded('sodium')) {
            yield 'chacha20-poly1305' => ['chacha20-poly1305'];
        }
    }
}
