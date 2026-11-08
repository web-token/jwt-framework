<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Before;
use Throwable;
use function array_key_exists;
use function array_unique;
use function array_values;
use function ini_get;
use function ini_set;
use function is_array;
use function is_string;
use function str_contains;
use function str_starts_with;

/**
 * PHP records the arguments of the pending calls when an exception is created, unless zend.exception_ignore_args is
 * enabled. The tests using this trait record them, whatever the configuration of the platform.
 */
trait ExceptionTraceArgumentsTrait
{
    private string|false $exceptionIgnoreArgs = false;

    #[Before]
    public function recordTheArgumentsOfTheExceptionTraces(): void
    {
        $this->exceptionIgnoreArgs = ini_get('zend.exception_ignore_args');
        ini_set('zend.exception_ignore_args', '0');
    }

    #[After]
    public function restoreTheExceptionTraceSettings(): void
    {
        if ($this->exceptionIgnoreArgs !== false) {
            ini_set('zend.exception_ignore_args', $this->exceptionIgnoreArgs);
        }
    }

    private static function failureOf(callable $call): Throwable
    {
        try {
            $call();
        } catch (Throwable $throwable) {
            return $throwable;
        }

        static::fail('No exception was thrown.');
    }

    private static function argumentsAreRecorded(Throwable $exception): bool
    {
        foreach ($exception->getTrace() as $frame) {
            if (array_key_exists('args', $frame)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Lists the calls of the exception chain, outside the tests and PHPUnit, with an argument containing the value.
     *
     * @return list<string>
     */
    private static function callsHolding(Throwable $exception, string $value): array
    {
        $calls = [];
        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            foreach ($current->getTrace() as $frame) {
                $class = $frame['class'] ?? '';
                if (str_starts_with($class, 'Jose\\Tests\\') || str_starts_with($class, 'PHPUnit\\')) {
                    continue;
                }
                if (self::holds($frame['args'] ?? [], $value)) {
                    $calls[] = $class . ($frame['type'] ?? '') . $frame['function'];
                }
            }
        }

        return array_values(array_unique($calls));
    }

    private static function holds(mixed $argument, string $value): bool
    {
        if (is_string($argument)) {
            return str_contains($argument, $value);
        }
        if (! is_array($argument)) {
            return false;
        }
        foreach ($argument as $item) {
            if (self::holds($item, $value)) {
                return true;
            }
        }

        return false;
    }
}
