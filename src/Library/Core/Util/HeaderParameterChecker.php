<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use function count;
use function implode;
use function sprintf;

/**
 * Checks the header parameters of a token against each other.
 *
 * @internal
 */
final class HeaderParameterChecker
{
    /**
     * Ensures the two given headers do not share any parameter.
     *
     * The protected, unprotected and per-recipient headers of a token are merged into a single JOSE header, hence a
     * parameter set in more than one of them is rejected: see RFC 7515 section 7.2.1 and RFC 7516 section 7.2.1.
     *
     * @param array<array-key, mixed> $header1
     * @param array<array-key, mixed> $header2
     */
    public static function checkDuplicates(array $header1, array $header2): void
    {
        $inter = array_intersect_key($header1, $header2);
        if (count($inter) !== 0) {
            throw new InvalidHeaderParameterException(sprintf(
                'The header contains duplicated entries: %s.',
                implode(', ', array_keys($inter))
            ));
        }
    }
}
