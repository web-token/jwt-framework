<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\JWK;

/**
 * A recipient of the JWE to build, as declared by a call to JWEBuilder::addRecipient().
 *
 * The specification is the immutable state of the builder: it holds what the caller provided, not the
 * encrypted content encryption key. Neither the key encryption algorithm nor the content encryption
 * algorithm belong to it, as both are read from the complete header, which is only known once the shared
 * headers are set: they are resolved by JWEBuilder::build(), whatever the order of the calls is.
 *
 * @internal
 */
final readonly class RecipientSpec
{
    /**
     * @param array<string, mixed> $header
     */
    public function __construct(
        public JWK $key,
        public array $header
    ) {
    }
}
