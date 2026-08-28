<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Throwable;

/**
 * Decrypts a recipient of a JWE.
 *
 * The interface is implemented by JWEDecrypter and by every object that decorates it. Decoration is the supported way
 * of plugging behaviour into the decrypter: JWEDecrypter is annotated as final and will be final in 5.0.0.
 *
 * The interface only declares the methods that will survive 5.0.0. "decryptUsingKey()" and "decryptUsingKeySet()",
 * deprecated since 4.3.0 because they replace variables of the caller, are still available on JWEDecrypter and on
 * the objects of this package that decorate it, but they are not part of the contract.
 */
interface JWEDecrypterInterface
{
    /**
     * Returns the key encryption algorithm manager.
     */
    public function getKeyEncryptionAlgorithmManager(): AlgorithmManager;

    /**
     * Returns the content encryption algorithm manager.
     */
    public function getContentEncryptionAlgorithmManager(): AlgorithmManager;

    /**
     * Decrypts the given recipient of the JWE using a key or a key set. The decrypted JWE and the key that decrypted
     * it are carried by the returned result: JWE objects are immutable, so the JWE given to this method is left
     * untouched.
     *
     * A key that cannot be used, or that does not decrypt the recipient, does not abort the decryption: the next key
     * of the key set is tried and the reason of the failure is otherwise lost. The optional callable is called with
     * every discarded Throwable, so that those failures can be observed.
     *
     * @param JWK|JWKSet $keys The recipient will be decrypted using that key or the keys in that key set
     * @param JWK|null $senderKey The sender key, when the key management algorithm is a static key agreement
     * @param (callable(Throwable): void)|null $onError Called with every failure met while trying the keys
     */
    public function decrypt(
        JWE $jwe,
        JWK|JWKSet $keys,
        int $recipientIndex,
        ?JWK $senderKey = null,
        ?callable $onError = null
    ): DecryptionResult;
}
