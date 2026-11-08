<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption\Util;

use AESKW\Wrapper;
use Jose\Component\Core\Exception\InvalidArgumentException;
use SensitiveParameter;
use Throwable;

/**
 * @internal
 */
final readonly class AESKeyWrap
{
    /**
     * A failure is rethrown without being chained: the trace of the exception thrown by the key wrapping library
     * records the key encryption key among the arguments.
     */
    public static function unwrap(Wrapper $wrapper, #[SensitiveParameter] string $kek, string $encryptedKey): string
    {
        try {
            return $wrapper::unwrap($kek, $encryptedKey);
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException($throwable->getMessage());
        }
    }
}
