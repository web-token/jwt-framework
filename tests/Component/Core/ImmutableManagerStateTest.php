<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

/**
 * A manager expresses a policy: the set of checkers or serializers it was built with cannot be widened afterwards, not
 * even from inside the class.
 *
 * @internal
 */
final class ImmutableManagerStateTest extends TestCase
{
    #[Test]
    #[DataProvider('managerState')]
    public function theStateOfTheManagerIsReadOnly(string $class, string $property): void
    {
        static::assertTrue((new ReflectionProperty($class, $property))->isReadOnly());
    }

    /**
     * @return iterable<array{string, string}>
     */
    public static function managerState(): iterable
    {
        yield [ClaimCheckerManager::class, 'checkers'];
        yield [HeaderCheckerManager::class, 'checkers'];
        yield [HeaderCheckerManager::class, 'tokenTypes'];
        yield [JWSSerializerManager::class, 'serializers'];
        yield [JWESerializerManager::class, 'serializers'];
    }
}
