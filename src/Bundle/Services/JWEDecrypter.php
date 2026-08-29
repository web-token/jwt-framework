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
use Jose\Component\Encryption\JWEDecrypter as BaseJWEDecrypter;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

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
     * The deprecated methods of the parent class are implemented on top of this one: the events are dispatched
     * whichever method the application calls.
     *
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
        $result = parent::decrypt($jwe, $keys, $recipientIndex, $senderKey, $onError);
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
}
