<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Jose\Component\Core\AlgorithmManager;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const E_USER_DEPRECATED;

/**
 * @internal
 */
final class AlgorithmManagerTest extends TestCase
{
    #[Test]
    public function theManagerIsBuiltFromTheAlgorithmsPassedToTheConstructor(): void
    {
        $algorithm = new FooAlgorithm();

        $sut = new AlgorithmManager([$algorithm]);

        static::assertTrue($sut->has('foo'));
        static::assertSame(['foo'], $sut->list());
        static::assertSame([
            'foo' => $algorithm,
        ], $sut->all());
        static::assertSame($algorithm, $sut->get('foo'));
    }

    #[Test]
    public function theConstructorDoesNotTriggerTheDeprecationOfTheAddMethod(): void
    {
        $deprecations = $this->collectDeprecations(static function (): void {
            new AlgorithmManager([new FooAlgorithm()]);
        });

        static::assertSame([], $deprecations);
    }

    #[Test]
    public function withReturnsANewManagerAndLeavesTheCurrentOneUntouched(): void
    {
        $sut = new AlgorithmManager([new FooAlgorithm()]);

        $new = $sut->with(new BarAlgorithm());

        static::assertNotSame($sut, $new);
        static::assertSame(['foo'], $sut->list());
        static::assertSame(['foo', 'bar'], $new->list());
    }

    #[Test]
    public function withAcceptsSeveralAlgorithmsAtOnce(): void
    {
        $sut = new AlgorithmManager([]);

        $new = $sut->with(new FooAlgorithm(), new BarAlgorithm());

        static::assertSame(['foo', 'bar'], $new->list());
    }

    #[Test]
    public function withReplacesAnAlgorithmThatHasTheSameName(): void
    {
        $replacement = new FooAlgorithm();
        $sut = new AlgorithmManager([new FooAlgorithm()]);

        $new = $sut->with($replacement);

        static::assertSame(['foo'], $new->list());
        static::assertSame($replacement, $new->get('foo'));
    }

    #[Test]
    public function withDoesNotTriggerAnyDeprecation(): void
    {
        $sut = new AlgorithmManager([new FooAlgorithm()]);

        $deprecations = $this->collectDeprecations(static function () use ($sut): void {
            $sut->with(new BarAlgorithm());
        });

        static::assertSame([], $deprecations);
    }

    #[Test]
    public function theAddMethodIsDeprecatedButStillMutatesTheManager(): void
    {
        $sut = new AlgorithmManager([new FooAlgorithm()]);
        $algorithm = new BarAlgorithm();

        $deprecations = $this->collectDeprecations(static function () use ($sut, $algorithm): void {
            $sut->add($algorithm);
        });

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'The method "Jose\Component\Core\AlgorithmManager::add()" is deprecated and will be removed in 5.0.0.',
            $deprecations[0]
        );
        static::assertSame($algorithm, $sut->get('bar'));
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
