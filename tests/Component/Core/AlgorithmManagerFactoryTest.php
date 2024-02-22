<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TypeError;

/**
 * @internal
 */
final class AlgorithmManagerFactoryTest extends TestCase
{
    private ?AlgorithmManagerFactory $algorithmManagerFactory = null;

    #[Test]
    public function iCanListSupportedAliases(): void
    {
        static::assertSame(['foo'], $this->getAlgorithmManagerFactory()->aliases());
        static::assertSame(['foo'], array_keys($this->getAlgorithmManagerFactory()->all()));
    }

    #[Test]
    public function iCannotCreateAnAlgorithmManagerWithABadArgument(): void
    {
        $this->expectException(TypeError::class);

        new AlgorithmManager(['foo']);
    }

    #[Test]
    public function iCannotGetAnAlgorithmThatDoesNotExist(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The algorithm "HS384" is not supported.');

        $manager = new AlgorithmManager([new FooAlgorithm()]);

        static::assertSame(['foo'], $manager->list());
        static::assertTrue($manager->has('foo'));
        static::assertFalse($manager->has('HS384'));
        $manager->get('HS384');
    }

    private function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if ($this->algorithmManagerFactory === null) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory([new FooAlgorithm()]);
        }

        return $this->algorithmManagerFactory;
    }
}
