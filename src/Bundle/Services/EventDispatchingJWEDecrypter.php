<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWEDecryptionFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWEDecryptionSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\DecryptionResult;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypterInterface;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;
use function func_get_arg;
use function func_num_args;
use function is_callable;
use function trigger_deprecation;

/**
 * Dispatches an event whenever a recipient is decrypted, without extending the decrypter it decorates.
 */
final readonly class EventDispatchingJWEDecrypter implements JWEDecrypterInterface
{
    public function __construct(
        private JWEDecrypterInterface $decrypter,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    #[Override]
    public function getKeyEncryptionAlgorithmManager(): AlgorithmManager
    {
        return $this->decrypter->getKeyEncryptionAlgorithmManager();
    }

    #[Override]
    public function getContentEncryptionAlgorithmManager(): AlgorithmManager
    {
        return $this->decrypter->getContentEncryptionAlgorithmManager();
    }

    /**
     * A JWE that already has a payload is reported as decrypted without any key being used. There is nothing to
     * report in that case, hence no event at all.
     *
     * @param (callable(Throwable): void)|null $onError
     */
    #[Override]
    public function decrypt(
        JWE $jwe,
        JWK|JWKSet $keys,
        int $recipientIndex,
        ?JWK $senderKey = null,
        ?callable $onError = null
    ): DecryptionResult {
        $result = $this->decrypter->decrypt($jwe, $keys, $recipientIndex, $senderKey, $onError);
        $jwkset = $keys instanceof JWK ? new JWKSet([$keys]) : $keys;
        $jwk = $result->getKey();
        if ($jwk !== null) {
            $this->eventDispatcher->dispatch(
                new JWEDecryptionSuccessEvent($result->getJwe(), $jwkset, $jwk, $recipientIndex)
            );
        } elseif (! $result->isDecrypted()) {
            $this->eventDispatcher->dispatch(new JWEDecryptionFailureEvent($jwe, $jwkset));
        }

        return $result;
    }

    /**
     * @deprecated since 4.3.0, use "decrypt()" instead. Will be removed in 5.0.0.
     */
    public function decryptUsingKey(JWE &$jwe, JWK $jwk, int $recipient, ?JWK $senderKey = null): bool
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::decryptUsingKey()" is deprecated and will be removed in 5.0.0. Please use "%s::decrypt()" instead: it returns a "%s" object that carries the decrypted JWE instead of replacing the variable of the caller.',
            self::class,
            self::class,
            DecryptionResult::class
        );
        $jwkset = new JWKSet([$jwk]);
        $successJwk = null;

        return $this->decryptUsingKeySet($jwe, $jwkset, $recipient, $successJwk, $senderKey);
    }

    /**
     * The callable used by the loaders to observe the keys that were discarded is not part of the signature: it is
     * read with func_num_args()/func_get_arg(5) and forwarded to "decrypt()", otherwise the reason of a failure would
     * be lost as soon as the decrypter is decorated.
     *
     * @param-out JWK|null $jwk
     *
     * @deprecated since 4.3.0, use "decrypt()" instead. Will be removed in 5.0.0.
     */
    public function decryptUsingKeySet(
        JWE &$jwe,
        JWKSet $jwkset,
        int $recipient,
        ?JWK &$jwk = null,
        ?JWK $senderKey = null
    ): bool {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::decryptUsingKeySet()" is deprecated and will be removed in 5.0.0. Please use "%s::decrypt()" instead: it returns a "%s" object that carries the decrypted JWE and the key instead of replacing the variables of the caller.',
            self::class,
            self::class,
            DecryptionResult::class
        );
        $onError = func_num_args() >= 6 ? func_get_arg(5) : null;
        if (! is_callable($onError)) {
            $onError = null;
        }
        $result = $this->decrypt($jwe, $jwkset, $recipient, $senderKey, $onError);
        if (! $result->isDecrypted()) {
            return false;
        }
        $jwe = $result->getJwe();
        $successJwk = $result->getKey();
        if ($successJwk !== null) {
            $jwk = $successJwk;
        }

        return true;
    }
}
