<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use RuntimeException;
use Throwable;
use function func_get_arg;
use function func_num_args;
use function is_int;
use function sprintf;

/**
 * @see \Jose\Tests\Component\Encryption\JWELoaderTest
 */
class JWELoader
{
    private readonly ?int $maxRecipients;

    /**
     * A fourth argument sets the maximum number of recipients of a token: a token with more is rejected before any
     * of them is processed. Without it, the number is not limited. That argument is not part of the signature yet (it
     * will be in 5.0.0) and is read with func_num_args()/func_get_arg(3), so that classes extending this one remain
     * compatible.
     */
    public function __construct(
        private readonly JWESerializerManager $serializerManager,
        private readonly JWEDecrypter $jweDecrypter,
        private readonly ?HeaderCheckerManager $headerCheckerManager
    ) {
        $maxRecipients = func_num_args() > 3 ? func_get_arg(3) : null;
        if ($maxRecipients !== null && (! is_int($maxRecipients) || $maxRecipients < 1)) {
            throw new InvalidArgumentException('The maximum number of recipients must be a positive integer.');
        }
        $this->maxRecipients = $maxRecipients;
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
     */
    public function loadAndDecryptWithKeySet(string $token, JWKSet $keyset, ?int &$recipient): JWE
    {
        try {
            $jwe = $this->serializerManager->unserialize($token);
            $nbRecipients = $jwe->countRecipients();
            if ($this->maxRecipients !== null && $nbRecipients > $this->maxRecipients) {
                throw new InvalidArgumentException(sprintf(
                    'The token has too many recipients. The maximum allowed number is %d.',
                    $this->maxRecipients
                ));
            }
            for ($i = 0; $i < $nbRecipients; ++$i) {
                if ($this->processRecipient($jwe, $keyset, $i)) {
                    $recipient = $i;

                    return $jwe;
                }
            }
        } catch (Throwable) {
            // Nothing to do. Exception thrown just after
        }

        throw new RuntimeException('Unable to load and decrypt the token.');
    }

    private function processRecipient(JWE &$jwe, JWKSet $keyset, int $recipient): bool
    {
        try {
            if ($this->headerCheckerManager !== null) {
                $this->headerCheckerManager->check($jwe, $recipient);
            }

            return $this->jweDecrypter->decryptUsingKeySet($jwe, $keyset, $recipient);
        } catch (Throwable) {
            return false;
        }
    }
}
