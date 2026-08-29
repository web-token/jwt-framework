<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use InvalidArgumentException;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\DecryptionFailedException;
use Jose\Component\Core\Exception\EncryptionFailedException;
use Jose\Component\Core\Exception\InvalidArgumentException as JoseInvalidArgumentException;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\InvalidKeySetException;
use Jose\Component\Core\Exception\InvalidPayloadException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\Exception\JoseException;
use Jose\Component\Core\Exception\LogicException as JoseLogicException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\Exception\MissingPayloadException;
use Jose\Component\Core\Exception\MissingPayloadLogicException;
use Jose\Component\Core\Exception\MissingPayloadRuntimeException;
use Jose\Component\Core\Exception\RangeException as JoseRangeException;
use Jose\Component\Core\Exception\RuntimeException as JoseRuntimeException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\Exception\UnsupportedCurveException;
use Jose\Component\Core\Exception\UnsupportedSerializerException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RangeException;
use ReflectionClass;
use RuntimeException;
use Throwable;
use function count;
use function sprintf;

/**
 * @internal
 */
final class JoseExceptionTest extends TestCase
{
    /**
     * The SPL parent of each exception is the class that was thrown before version 4.3.0.
     *
     * @var array<class-string, class-string>
     */
    private const SPL_PARENTS = [
        DecryptionFailedException::class => RuntimeException::class,
        EncryptionFailedException::class => RuntimeException::class,
        JoseInvalidArgumentException::class => InvalidArgumentException::class,
        InvalidHeaderParameterException::class => InvalidArgumentException::class,
        InvalidKeyException::class => InvalidArgumentException::class,
        InvalidKeySetException::class => InvalidArgumentException::class,
        InvalidPayloadException::class => InvalidArgumentException::class,
        InvalidSerializationException::class => InvalidArgumentException::class,
        InvalidTokenException::class => RuntimeException::class,
        JoseLogicException::class => LogicException::class,
        MissingDependencyException::class => RuntimeException::class,
        MissingPayloadLogicException::class => LogicException::class,
        MissingPayloadRuntimeException::class => RuntimeException::class,
        JoseRangeException::class => RangeException::class,
        JoseRuntimeException::class => RuntimeException::class,
        UnsupportedAlgorithmException::class => InvalidArgumentException::class,
        UnsupportedCurveException::class => InvalidArgumentException::class,
        UnsupportedSerializerException::class => InvalidArgumentException::class,
    ];

    #[Test]
    public function everyExceptionOfTheLibraryImplementsTheMarkerInterface(): void
    {
        $classes = self::exceptionClasses();
        static::assertGreaterThan(0, count($classes));
        foreach ($classes as $class) {
            static::assertTrue(
                is_a($class, JoseException::class, true),
                sprintf('%s does not implement %s.', $class, JoseException::class)
            );
        }
    }

    /**
     * The SPL parent of each exception is the class that was thrown before version 4.3.0. Changing it would
     * silently break the catch blocks written for the previous versions.
     */
    #[Test]
    #[DataProvider('splParents')]
    public function theExceptionsKeepTheSplParentThrownByThePreviousVersions(string $class, string $parent): void
    {
        static::assertTrue(is_a($class, $parent, true), sprintf('%s does not extend %s.', $class, $parent));
    }

    #[Test]
    public function anUnsupportedAlgorithmIsReported(): void
    {
        $manager = new AlgorithmManager([]);

        $throwable = self::capture(static fn () => $manager->get('HS256'));

        static::assertInstanceOf(UnsupportedAlgorithmException::class, $throwable);
        static::assertInstanceOf(InvalidArgumentException::class, $throwable);
    }

    #[Test]
    public function anInvalidKeyIsReported(): void
    {
        $throwable = self::capture(static fn () => new JWK([
            'foo' => 'bar',
        ]));

        static::assertInstanceOf(InvalidKeyException::class, $throwable);
        static::assertInstanceOf(InvalidArgumentException::class, $throwable);
    }

    #[Test]
    public function anInvalidKeySetIsReported(): void
    {
        $throwable = self::capture(static fn () => JWKSet::createFromKeyData([]));

        static::assertInstanceOf(InvalidKeySetException::class, $throwable);
        static::assertInstanceOf(InvalidArgumentException::class, $throwable);
    }

    #[Test]
    public function aMalformedBase64UrlStringIsReported(): void
    {
        $throwable = self::capture(static fn () => Base64UrlSafe::decode('a', true));

        static::assertInstanceOf(JoseException::class, $throwable);
        static::assertInstanceOf(RangeException::class, $throwable);
    }

    /**
     * The JWS and the JWE builders report the missing payload with the same interface, even though they kept
     * the two distinct SPL parents they used before version 4.3.0.
     */
    #[Test]
    public function aMissingPayloadIsReportedTheSameWayByBothBuilders(): void
    {
        $fromJws = self::capture(static fn () => (new JWSBuilder(new AlgorithmManager([])))->build());
        $fromJwe = self::capture(static fn () => (new JWEBuilder(new AlgorithmManager([])))->build());

        static::assertInstanceOf(MissingPayloadException::class, $fromJws);
        static::assertInstanceOf(MissingPayloadException::class, $fromJwe);

        static::assertInstanceOf(MissingPayloadRuntimeException::class, $fromJws);
        static::assertInstanceOf(RuntimeException::class, $fromJws);
        static::assertInstanceOf(MissingPayloadLogicException::class, $fromJwe);
        static::assertInstanceOf(LogicException::class, $fromJwe);
    }

    #[Test]
    public function anUnsupportedSerializationIsReportedWithItsCause(): void
    {
        $manager = new JWSSerializerManager([new CompactSerializer()]);

        $throwable = self::capture(static fn () => $manager->unserialize('Hello world!'));

        static::assertInstanceOf(InvalidSerializationException::class, $throwable);
        static::assertInstanceOf(JoseException::class, $throwable->getPrevious());
    }

    #[Test]
    public function theHeaderCheckerFailuresBelongToTheHierarchy(): void
    {
        $checker = new AlgorithmChecker(['HS256']);

        $throwable = self::capture(static fn () => $checker->checkHeader('none'));

        static::assertInstanceOf(InvalidHeaderException::class, $throwable);
        static::assertInstanceOf(JoseException::class, $throwable);
    }

    /**
     * @return iterable<array{0: class-string, 1: class-string}>
     */
    public static function splParents(): iterable
    {
        foreach (self::SPL_PARENTS as $class => $parent) {
            yield $class => [$class, $parent];
        }
    }

    #[Test]
    public function theSplParentOfEveryExceptionIsUnderContract(): void
    {
        $concrete = array_filter(
            self::exceptionClasses(),
            static fn (string $class): bool => ! (new ReflectionClass($class))->isInterface()
        );

        static::assertSame([], array_diff($concrete, array_keys(self::SPL_PARENTS)));
    }

    /**
     * @return array<class-string>
     */
    private static function exceptionClasses(): array
    {
        $classes = [];
        foreach (glob(__DIR__ . '/../../../src/Library/Core/Exception/*.php') ?: [] as $file) {
            $class = 'Jose\Component\Core\Exception\\' . basename($file, '.php');
            if ($class !== JoseException::class) {
                $classes[] = $class;
            }
        }

        return $classes;
    }

    private static function capture(callable $callable): Throwable
    {
        try {
            $callable();
        } catch (Throwable $throwable) {
            return $throwable;
        }

        static::fail('No exception thrown.');
    }
}
