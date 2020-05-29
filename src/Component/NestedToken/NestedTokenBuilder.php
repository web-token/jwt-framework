<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\NestedToken;

use function array_key_exists;
use InvalidArgumentException;
use function is_array;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

class NestedTokenBuilder
{
    /**
     * @var JWSBuilder
     */
    private $jwsBuilder;

    /**
     * @var JWSSerializerManager
     */
    private $jwsSerializerManager;

    /**
     * @var JWEBuilder
     */
    private $jweBuilder;

    /**
     * @var JWESerializerManager
     */
    private $jweSerializerManager;

    public function __construct(JWEBuilder $jweBuilder, JWESerializerManager $jweSerializerManager, JWSBuilder $jwsBuilder, JWSSerializerManager $jwsSerializerManager)
    {
        $this->jweBuilder = $jweBuilder;
        $this->jwsSerializerManager = $jwsSerializerManager;
        $this->jwsBuilder = $jwsBuilder;
        $this->jweSerializerManager = $jweSerializerManager;
    }

    /**
     * Creates a nested token.
     *
     * @throws InvalidArgumentException if the argument "$signatures" does not include the expected structure
     * @throws InvalidArgumentException if the argument "$recipients" does not include the expected structure
     */
    public function create(string $payload, array $signatures, string $jws_serialization_mode, array $jweSharedProtectedHeader, array $jweSharedHeader, array $recipients, string $jwe_serialization_mode, ?string $aad = null): string
    {
        $jws = $this->jwsBuilder->create()->withPayload($payload);
        foreach ($signatures as $signature) {
            if (!is_array($signature) || !array_key_exists('key', $signature)) {
                throw new InvalidArgumentException('The signatures must be an array of arrays containing a key, a protected header and a header');
            }
            $signature['protected_header'] = array_key_exists('protected_header', $signature) ? $signature['protected_header'] : [];
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
            ->withAAD($aad)
        ;
        foreach ($recipients as $recipient) {
            if (!is_array($recipient) || !array_key_exists('key', $recipient)) {
                throw new InvalidArgumentException('The recipients must be an array of arrays containing a key and a header');
            }
            $recipient['header'] = array_key_exists('header', $recipient) ? $recipient['header'] : [];
            $jwe = $jwe->addRecipient($recipient['key'], $recipient['header']);
        }
        $jwe = $jwe->build();

        return $this->jweSerializerManager->serialize($jwe_serialization_mode, $jwe);
    }
}
