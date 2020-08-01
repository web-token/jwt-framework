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

namespace Jose\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use RuntimeException;
use Throwable;

class JWELoader
{
    /**
     * @var JWEDecrypter
     */
    private $jweDecrypter;

    /**
     * @var null|HeaderCheckerManager
     */
    private $headerCheckerManager;

    /**
     * @var JWESerializerManager
     */
    private $serializerManager;

    /**
     * JWELoader constructor.
     */
    public function __construct(JWESerializerManager $serializerManager, JWEDecrypter $jweDecrypter, ?HeaderCheckerManager $headerCheckerManager)
    {
        $this->serializerManager = $serializerManager;
        $this->jweDecrypter = $jweDecrypter;
        $this->headerCheckerManager = $headerCheckerManager;
    }

    /**
     * Returns the JWE Decrypter object.
     */
    public function getJweDecrypter(): JWEDecrypter
    {
        return $this->jweDecrypter;
    }

    /**
     * Returns the header checker manager if set.
     */
    public function getHeaderCheckerManager(): ?HeaderCheckerManager
    {
        return $this->headerCheckerManager;
    }

    /**
     * Returns the serializer manager.
     */
    public function getSerializerManager(): JWESerializerManager
    {
        return $this->serializerManager;
    }

    /**
     * This method will try to load and decrypt the given token using a JWK.
     * If succeeded, the methods will populate the $recipient variable and returns the JWE.
     */
    public function loadAndDecryptWithKey(string $token, JWK $key, ?int &$recipient): JWE
    {
        $keyset = new JWKSet([$key]);

        return $this->loadAndDecryptWithKeySet($token, $keyset, $recipient);
    }

    /**
     * This method will try to load and decrypt the given token using a JWKSet.
     * If succeeded, the methods will populate the $recipient variable and returns the JWE.
     *
     * @throws RuntimeException if the data cannot be loaded or decrypted
     */
    public function loadAndDecryptWithKeySet(string $token, JWKSet $keyset, ?int &$recipient): JWE
    {
        try {
            $jwe = $this->serializerManager->unserialize($token);
            $nbRecipients = $jwe->countRecipients();
            for ($i = 0; $i < $nbRecipients; ++$i) {
                if ($this->processRecipient($jwe, $keyset, $i)) {
                    $recipient = $i;

                    return $jwe;
                }
            }
        } catch (Throwable $e) {
            // Nothing to do. Exception thrown just after
        }

        throw new RuntimeException('Unable to load and decrypt the token.');
    }

    private function processRecipient(JWE &$jwe, JWKSet $keyset, int $recipient): bool
    {
        try {
            if (null !== $this->headerCheckerManager) {
                $this->headerCheckerManager->check($jwe, $recipient);
            }

            return $this->jweDecrypter->decryptUsingKeySet($jwe, $keyset, $recipient);
        } catch (Throwable $e) {
            return false;
        }
    }
}
