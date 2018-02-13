<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Serializer\JWESerializerManager;

final class JWELoader
{
    /**
     * @var JWEDecrypter
     */
    private $jweDecrypter;

    /**
     * @var HeaderCheckerManager
     */
    private $headerCheckerManager;

    /**
     * @var JWESerializerManager
     */
    private $serializerManager;

    /**
     * JWELoader constructor.
     *
     * @param JWESerializerManager $serializerManager
     * @param JWEDecrypter         $jweDecrypter
     * @param HeaderCheckerManager $headerCheckerManager
     */
    public function __construct(JWESerializerManager $serializerManager, JWEDecrypter $jweDecrypter, HeaderCheckerManager $headerCheckerManager)
    {
        $this->serializerManager = $serializerManager;
        $this->jweDecrypter = $jweDecrypter;
        $this->headerCheckerManager = $headerCheckerManager;
    }

    /**
     * @param string $token
     * @param JWK    $key
     * @param int    $recipient
     *
     * @return JWE
     */
    public function loadAndDecryptWithKey(string $token, JWK $key, int &$recipient): JWE
    {
        $keyset = JWKSet::createFromKeys([$key]);

        return $this->loadAndDecryptWithKeySet($token, $keyset, $recipient);
    }

    /**
     * @param string $token
     * @param JWKSet $keyset
     * @param int    $recipient
     *
     * @throws \Exception
     *
     * @return JWE
     */
    public function loadAndDecryptWithKeySet(string $token, JWKSet $keyset, int &$recipient): JWE
    {
        try {
            $jwe = $this->serializerManager->unserialize($token);
            $nbRecipients = $jwe->countRecipients();
            for ($i = 0; $i < $nbRecipients; $i++) {
                if ($this->processRecipient($jwe, $keyset, $i)) {
                    $recipient = $i;

                    return $jwe;
                }
            }
        } catch (\Exception $e) {
            // Nothing to do. Exception thrown just after
        }

        throw new \Exception('Unable to load the token.');
    }

    /**
     * @param JWE    $jwe
     * @param JWKSet $keyset
     * @param int    $recipient
     *
     * @return bool
     */
    private function processRecipient(JWE &$jwe, JWKSet $keyset, int $recipient): bool
    {
        try {
            $this->headerCheckerManager->check($jwe, $recipient);

            return $this->jweDecrypter->decryptUsingKeySet($jwe, $keyset, $recipient);
        } catch (\Exception $e) {
            return false;
        }
    }
}
