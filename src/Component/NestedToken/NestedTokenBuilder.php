<?php

declare(strict_types=1);

namespace Jose\Component\NestedToken;

use function array_key_exists;
use InvalidArgumentException;
use function is_array;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

class NestedTokenBuilder
{
    public function __construct(
        private readonly JWEBuilder $jweBuilder,
        private readonly JWESerializerManager $jweSerializerManager,
        private readonly JWSBuilder $jwsBuilder,
        private readonly JWSSerializerManager $jwsSerializerManager
    ) {
    }

    /**
     * Creates a nested token.
     *
     * @param array{array{key: JWK, protected_header?: array<string, mixed>, header?: array<string, mixed>}} $signatures
     * @param array{alg?: string, string?: mixed} $jweSharedProtectedHeader
     * @param array{alg?: string, string?: mixed} $jweSharedHeader
     * @param array{array{key: JWK, header?: array<string, mixed>}} $recipients
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
        $jws = $this->jwsBuilder->create()
            ->withPayload($payload);
        foreach ($signatures as $signature) {
            if (! is_array($signature) || ! array_key_exists('key', $signature)) {
                throw new InvalidArgumentException(
                    'The signatures must be an array of arrays containing a key, a protected header and a header'
                );
            }
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
            ->create()
            ->withPayload($token)
            ->withSharedProtectedHeader($jweSharedProtectedHeader)
            ->withSharedHeader($jweSharedHeader)
            ->withAAD($aad);
        foreach ($recipients as $recipient) {
            if (! is_array($recipient) || ! array_key_exists('key', $recipient)) {
                throw new InvalidArgumentException(
                    'The recipients must be an array of arrays containing a key and a header'
                );
            }
            $recipient['header'] = array_key_exists('header', $recipient) ? $recipient['header'] : [];
            $jwe = $jwe->addRecipient($recipient['key'], $recipient['header']);
        }
        $jwe = $jwe->build();

        return $this->jweSerializerManager->serialize($jwe_serialization_mode, $jwe);
    }
}
