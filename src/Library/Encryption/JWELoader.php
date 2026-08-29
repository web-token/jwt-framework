<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\InheritanceChecker;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Throwable;
use function trigger_deprecation;

/**
 * @final The class will be final in 5.0.0: implement JWELoaderInterface and decorate the service instead of
 * extending it.
 *
 * @see \Jose\Tests\Component\Encryption\JWELoaderTest
 */
class JWELoader implements JWELoaderInterface
{
    public function __construct(
        private readonly JWESerializerManager $serializerManager,
        private readonly JWEDecrypterInterface $jweDecrypter,
        private readonly ?HeaderCheckerManagerInterface $headerCheckerManager
    ) {
        InheritanceChecker::warnIfExtended(static::class, self::class, JWELoaderInterface::class);
    }

    /**
     * Returns the JWE Decrypter object.
     */
    public function getJweDecrypter(): JWEDecrypterInterface
    {
        return $this->jweDecrypter;
    }

    /**
     * Returns the header checker manager if set.
     */
    public function getHeaderCheckerManager(): ?HeaderCheckerManagerInterface
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
     *
     * @param-out int $recipient
     *
     * @deprecated since 4.3.0, use "loadAndDecrypt()" instead. Will be removed in 5.0.0.
     */
    public function loadAndDecryptWithKey(string $token, JWK $key, ?int &$recipient): JWE
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::loadAndDecryptWithKey()" is deprecated and will be removed in 5.0.0. Please use "%s::loadAndDecrypt()" instead: it returns a "%s" object that carries the index of the decrypted recipient instead of writing it into a variable of the caller.',
            self::class,
            self::class,
            LoadingResult::class
        );
        $keyset = new JWKSet([$key]);

        return $this->loadAndDecryptWithKeySet($token, $keyset, $recipient);
    }

    /**
     * This method will try to load and decrypt the given token using a JWKSet. If succeeded, the methods will populate
     * the $recipient variable and returns the JWE.
     *
     * @param-out int $recipient
     *
     * @deprecated since 4.3.0, use "loadAndDecrypt()" instead. Will be removed in 5.0.0.
     */
    public function loadAndDecryptWithKeySet(string $token, JWKSet $keyset, ?int &$recipient): JWE
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::loadAndDecryptWithKeySet()" is deprecated and will be removed in 5.0.0. Please use "%s::loadAndDecrypt()" instead: it returns a "%s" object that carries the index of the decrypted recipient instead of writing it into a variable of the caller.',
            self::class,
            self::class,
            LoadingResult::class
        );
        $result = $this->loadAndDecrypt($token, $keyset);
        $recipient = $result->getRecipientIndex();

        return $result->getJwe();
    }

    /**
     * This method will try to load and decrypt the given token using a key or a key set. The decrypted JWE, the index
     * of the decrypted recipient and the key that decrypted it are carried by the returned result, otherwise an
     * exception is thrown.
     *
     * The failure semantics are unchanged, but the last error met along the way - a serialization failure, a rejected
     * header or a key that could not decrypt the recipient - is chained as the previous exception, so that the reason
     * of the failure remains available to the caller.
     *
     * @param string $token A string that represents a JWE
     * @param JWK|JWKSet $keys The recipient will be decrypted using that key or the keys in that key set
     */
    public function loadAndDecrypt(string $token, JWK|JWKSet $keys): LoadingResult
    {
        $lastError = null;
        try {
            $jwe = $this->serializerManager->unserialize($token);
            $nbRecipients = $jwe->countRecipients();
            for ($i = 0; $i < $nbRecipients; ++$i) {
                $result = $this->processRecipient($jwe, $keys, $i, $lastError);
                if ($result !== null && $result->isDecrypted()) {
                    return new LoadingResult($result->getJwe(), $i, $result->getKey());
                }
            }
        } catch (Throwable $throwable) {
            $lastError = $throwable;
        }

        throw new InvalidTokenException('Unable to load and decrypt the token.', 0, $lastError);
    }

    private function processRecipient(
        JWE $jwe,
        JWK|JWKSet $keys,
        int $recipient,
        ?Throwable &$lastError
    ): ?DecryptionResult {
        try {
            if ($this->headerCheckerManager !== null) {
                $this->headerCheckerManager->check($jwe, $recipient);
            }

            return $this->jweDecrypter->decrypt(
                $jwe,
                $keys,
                $recipient,
                null,
                static function (Throwable $throwable) use (&$lastError): void {
                    $lastError = $throwable;
                }
            );
        } catch (Throwable $throwable) {
            $lastError = $throwable;

            return null;
        }
    }
}
