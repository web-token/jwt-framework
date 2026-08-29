<?php

declare(strict_types=1);

namespace Jose\Component\NestedToken;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\InheritanceChecker;
use Jose\Component\Encryption\JWEBuilderInterface;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Signature\JWSBuilderInterface;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use function array_key_exists;

/**
 * @final The class will be final in 5.0.0: implement NestedTokenBuilderInterface and decorate the service instead of
 * extending it.
 */
class NestedTokenBuilder implements NestedTokenBuilderInterface
{
    public function __construct(
        private readonly JWEBuilderInterface $jweBuilder,
        private readonly JWESerializerManager $jweSerializerManager,
        private readonly JWSBuilderInterface $jwsBuilder,
        private readonly JWSSerializerManager $jwsSerializerManager
    ) {
        InheritanceChecker::warnIfExtended(static::class, self::class, NestedTokenBuilderInterface::class);
    }

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
    ): string {
        $jws = $this->jwsBuilder->withPayload($payload);
        foreach ($signatures as $signature) {
            $signature['protected_header'] = array_key_exists(
                'protected_header',
                $signature
            ) ? $signature['protected_header'] : [];
            $signature['header'] = array_key_exists('header', $signature) ? $signature['header'] : [];
            $jws = $jws->addSignature($signature['key'], $signature['protected_header'], $signature['header']);
        }
        $jws = $jws->build();
        $token = $this->jwsSerializerManager->serialize($jws_serialization_mode, $jws);

        $jweSharedProtectedHeader['cty'] = 'JWT';

        $jwe = $this->jweBuilder
            ->withPayload($token)
            ->withSharedProtectedHeader($jweSharedProtectedHeader)
            ->withSharedHeader($jweSharedHeader)
            ->withAAD($aad);
        foreach ($recipients as $recipient) {
            $recipient['header'] = array_key_exists('header', $recipient) ? $recipient['header'] : [];
            $jwe = $jwe->addRecipient($recipient['key'], $recipient['header']);
        }
        $jwe = $jwe->build();

        return $this->jweSerializerManager->serialize($jwe_serialization_mode, $jwe);
    }
}
