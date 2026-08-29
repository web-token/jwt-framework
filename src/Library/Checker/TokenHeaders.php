<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

/**
 * The two headers a token type support reads for one signature or for one recipient of a token.
 *
 * It is the return type announced for TokenTypeSupport::retrieveTokenHeaders() in 5.0.0, where it replaces the
 * "array &$protectedHeader" and "array &$unprotectedHeader" output parameters. It is not used by the interface yet:
 * adding it now would break every third-party implementation of it.
 *
 * A support given a token it does not handle returns an object carrying two empty headers, which is what it does
 * today by leaving the two output parameters untouched.
 */
final readonly class TokenHeaders
{
    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $unprotectedHeader
     */
    public function __construct(
        private array $protectedHeader = [],
        private array $unprotectedHeader = []
    ) {
    }

    /**
     * The header the token protects, empty when it protects none.
     *
     * @return array<string, mixed>
     */
    public function getProtectedHeader(): array
    {
        return $this->protectedHeader;
    }

    /**
     * The header the token does not protect, empty when it carries none. A JWE merges the shared unprotected header
     * and the header of the selected recipient into it.
     *
     * @return array<string, mixed>
     */
    public function getUnprotectedHeader(): array
    {
        return $this->unprotectedHeader;
    }
}
