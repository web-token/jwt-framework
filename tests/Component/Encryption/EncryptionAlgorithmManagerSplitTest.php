<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Signature\Algorithm\HS256;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const E_USER_DEPRECATED;

/**
 * The JWE builder and the JWE decrypter receive a single algorithm manager they split in two: the key encryption
 * algorithms and the content encryption algorithms. An algorithm that is neither is dropped, which is deprecated.
 *
 * @internal
 */
final class EncryptionAlgorithmManagerSplitTest extends TestCase
{
    #[Test]
    public function theBuilderSplitsTheAlgorithmManager(): void
    {
        $builder = new JWEBuilder(new AlgorithmManager([new A128KW(), new A128GCM()]));

        static::assertSame(['A128KW'], $builder->getKeyEncryptionAlgorithmManager()->list());
        static::assertSame(['A128GCM'], $builder->getContentEncryptionAlgorithmManager()->list());
    }

    #[Test]
    public function theDecrypterSplitsTheAlgorithmManager(): void
    {
        $decrypter = new JWEDecrypter(new AlgorithmManager([new A128KW(), new A128GCM()]));

        static::assertSame(['A128KW'], $decrypter->getKeyEncryptionAlgorithmManager()->list());
        static::assertSame(['A128GCM'], $decrypter->getContentEncryptionAlgorithmManager()->list());
    }

    #[Test]
    public function noDeprecationIsTriggeredWhenAllTheAlgorithmsAreEncryptionAlgorithms(): void
    {
        $algorithmManager = new AlgorithmManager([new A128KW(), new A128GCM()]);

        $deprecations = $this->collectDeprecations(static function () use ($algorithmManager): void {
            new JWEBuilder($algorithmManager);
            new JWEDecrypter($algorithmManager);
        });

        static::assertSame([], $deprecations);
    }

    #[Test]
    public function theBuilderDeprecatesTheAlgorithmsItDrops(): void
    {
        $algorithmManager = new AlgorithmManager([new A128KW(), new A128GCM(), new HS256()]);

        $builder = null;
        $deprecations = $this->collectDeprecations(static function () use ($algorithmManager, &$builder): void {
            $builder = new JWEBuilder($algorithmManager);
        });

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(JWEBuilder::class, $deprecations[0]);
        static::assertStringContainsString('HS256', $deprecations[0]);
        static::assertSame(['A128KW'], $builder->getKeyEncryptionAlgorithmManager()->list());
        static::assertSame(['A128GCM'], $builder->getContentEncryptionAlgorithmManager()->list());
    }

    #[Test]
    public function theDecrypterDeprecatesTheAlgorithmsItDrops(): void
    {
        $algorithmManager = new AlgorithmManager([new A128KW(), new A128GCM(), new HS256()]);

        $decrypter = null;
        $deprecations = $this->collectDeprecations(static function () use ($algorithmManager, &$decrypter): void {
            $decrypter = new JWEDecrypter($algorithmManager);
        });

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(JWEDecrypter::class, $deprecations[0]);
        static::assertStringContainsString('HS256', $deprecations[0]);
        static::assertSame(['A128KW'], $decrypter->getKeyEncryptionAlgorithmManager()->list());
        static::assertSame(['A128GCM'], $decrypter->getContentEncryptionAlgorithmManager()->list());
    }

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
