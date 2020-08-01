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

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWEDecryptionFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWEDecryptionSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypter as BaseJWEDecrypter;
use Psr\EventDispatcher\EventDispatcherInterface;

final class JWEDecrypter extends BaseJWEDecrypter
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    public function __construct(AlgorithmManager $keyEncryptionAlgorithmManager, AlgorithmManager $contentEncryptionAlgorithmManager, CompressionMethodManager $compressionMethodManager, EventDispatcherInterface $eventDispatcher)
    {
        parent::__construct($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager);
        $this->eventDispatcher = $eventDispatcher;
    }

    public function decryptUsingKeySet(JWE &$jwe, JWKSet $jwkset, int $recipient, JWK &$jwk = null, ?JWK $senderKey = null): bool
    {
        $success = parent::decryptUsingKeySet($jwe, $jwkset, $recipient, $jwk, $senderKey);
        if ($success) {
            $this->eventDispatcher->dispatch(new JWEDecryptionSuccessEvent(
                $jwe,
                $jwkset,
                $jwk,
                $recipient
            ));
        } else {
            $this->eventDispatcher->dispatch(new JWEDecryptionFailureEvent(
                $jwe,
                $jwkset
            ));
        }

        return $success;
    }
}
