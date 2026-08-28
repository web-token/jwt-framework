<?php

declare(strict_types=1);

namespace Jose\Component\NestedToken;

use Jose\Component\Core\JWK;

/**
 * Builds a nested token: a JWS serialized as the payload of a JWE.
 *
 * The interface is implemented by NestedTokenBuilder and by every object that decorates it. Decoration is the
 * supported way of plugging behaviour into the builder: NestedTokenBuilder is annotated as final and will be final in
 * 5.0.0.
 */
interface NestedTokenBuilderInterface
{
    /**
     * Creates a nested token.
     *
     * @param array<array{key: JWK, protected_header?: array<string, mixed>, header?: array<string, mixed>}> $signatures
     * @param array<string, mixed> $jweSharedProtectedHeader
     * @param array<string, mixed> $jweSharedHeader
     * @param array<array{key: JWK, header?: array<string, mixed>}> $recipients
     */
    public function create(
        string $payload,
        array $signatures,
        string $jws_serialization_mode,
        array $jweSharedProtectedHeader,
        array $jweSharedHeader,
        array $recipients,
        string $jwe_serialization_mode,
        ?string $aad = null
    ): string;
}
