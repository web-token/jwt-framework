<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use RuntimeException;
use Throwable;

/**
 * @see \Jose\Tests\Component\Encryption\JWELoaderTest
 */
class JWELoader
{
    public function __construct(
        private readonly JWESerializerManager $serializerManager,
        private readonly JWEDecrypter $jweDecrypter,
        private readonly ?HeaderCheckerManager $headerCheckerManager
    ) {
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
     * This method will try to load and decrypt the given token using a JWK. If succeeded, the methods will populate the
     * $recipient variable and returns the JWE.
     */
    public function loadAndDecryptWithKey(string $token, JWK $key, ?int &$recipient): JWE
    {
        $keyset = new JWKSet([$key]);

        return $this->loadAndDecryptWithKeySet($token, $keyset, $recipient);
    }

    /**
     * This method will try to load and decrypt the given token using a JWKSet. If succeeded, the methods will populate
     * the $recipient variable and returns the JWE.
     *
     * The failure semantics are unchanged, but the last error met along the way - a serialization failure, a rejected
     * header or a key that could not decrypt the recipient - is chained as the previous exception, so that the reason
     * of the failure remains available to the caller.
     */
    public function loadAndDecryptWithKeySet(string $token, JWKSet $keyset, ?int &$recipient): JWE
    {
        $lastError = null;
        try {
            $jwe = $this->serializerManager->unserialize($token);
            $nbRecipients = $jwe->countRecipients();
            for ($i = 0; $i < $nbRecipients; ++$i) {
                if ($this->processRecipient($jwe, $keyset, $i, $lastError)) {
                    $recipient = $i;

                    return $jwe;
                }
            }
        } catch (Throwable $throwable) {
            $lastError = $throwable;
        }

        throw new RuntimeException('Unable to load and decrypt the token.', 0, $lastError);
    }

    private function processRecipient(JWE &$jwe, JWKSet $keyset, int $recipient, ?Throwable &$lastError): bool
    {
        try {
            if ($this->headerCheckerManager !== null) {
                $this->headerCheckerManager->check($jwe, $recipient);
            }
            $jwk = null;

            return $this->jweDecrypter->decryptUsingKeySet(
                $jwe,
                $keyset,
                $recipient,
                $jwk,
                null,
                static function (Throwable $throwable) use (&$lastError): void {
                    $lastError = $throwable;
                }
            );
        } catch (Throwable $throwable) {
            $lastError = $throwable;

            return false;
        }
    }
}
