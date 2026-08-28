<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWEDecryptionFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWEDecryptionSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypterInterface;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use function func_get_arg;
use function func_num_args;

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

    #[Override]
    public function decryptUsingKey(JWE &$jwe, JWK $jwk, int $recipient, ?JWK $senderKey = null): bool
    {
        $jwkset = new JWKSet([$jwk]);
        $successJwk = null;

        return $this->decryptUsingKeySet($jwe, $jwkset, $recipient, $successJwk, $senderKey);
    }

    /**
     * The callable used by the loaders to observe the keys that were discarded is not part of the signature yet: it is
     * read with func_num_args()/func_get_arg(5) and forwarded to the decorated decrypter, otherwise the reason of a
     * failure would be lost as soon as the decrypter is decorated.
     */
    #[Override]
    public function decryptUsingKeySet(
        JWE &$jwe,
        JWKSet $jwkset,
        int $recipient,
        ?JWK &$jwk = null,
        ?JWK $senderKey = null
    ): bool {
        $success = func_num_args() >= 6 ? $this->decrypter->decryptUsingKeySet(
            $jwe,
            $jwkset,
            $recipient,
            $jwk,
            $senderKey,
            func_get_arg(5)
        ) : $this->decrypter->decryptUsingKeySet($jwe, $jwkset, $recipient, $jwk, $senderKey);

        if ($success) {
            $this->eventDispatcher->dispatch(new JWEDecryptionSuccessEvent($jwe, $jwkset, $jwk, $recipient));
        } else {
            $this->eventDispatcher->dispatch(new JWEDecryptionFailureEvent($jwe, $jwkset));
        }

        return $success;
    }
}
