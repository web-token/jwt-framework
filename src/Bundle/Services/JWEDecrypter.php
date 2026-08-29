<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWEDecryptionFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWEDecryptionSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypter as BaseJWEDecrypter;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use function func_get_arg;
use function func_num_args;

/**
 * @deprecated since 4.3.0, use EventDispatchingJWEDecrypter instead. The class extends a service of
 * the library that will be final in 5.0.0.
 */
final class JWEDecrypter extends BaseJWEDecrypter
{
    public function __construct(
        AlgorithmManager $algorithmManager,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($algorithmManager);
    }

    /**
     * The callable used by the loaders to observe the keys that were discarded is not part of the signature yet:
     * it is read with func_num_args()/func_get_arg(5) and forwarded to the parent, otherwise the reason of a
     * failure would be lost as soon as this service is used in place of the decrypter of the library.
     */
    #[Override]
    public function decryptUsingKeySet(
        JWE &$jwe,
        JWKSet $jwkset,
        int $recipient,
        ?JWK &$jwk = null,
        ?JWK $senderKey = null
    ): bool {
        $success = func_num_args() >= 6 ? parent::decryptUsingKeySet(
            $jwe,
            $jwkset,
            $recipient,
            $jwk,
            $senderKey,
            func_get_arg(5)
        ) : parent::decryptUsingKeySet($jwe, $jwkset, $recipient, $jwk, $senderKey);
        if ($success) {
            $this->eventDispatcher->dispatch(new JWEDecryptionSuccessEvent($jwe, $jwkset, $jwk, $recipient));
        } else {
            $this->eventDispatcher->dispatch(new JWEDecryptionFailureEvent($jwe, $jwkset));
        }

        return $success;
    }
}
