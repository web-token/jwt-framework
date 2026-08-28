<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

/**
 * Decrypts a recipient of a JWE.
 *
 * The interface is implemented by JWEDecrypter and by every object that decorates it. Decoration is the supported way
 * of plugging behaviour into the decrypter: JWEDecrypter is annotated as final and will be final in 5.0.0.
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
     * Decrypts the given recipient of the JWE using the given key.
     *
     * @param JWK|null $senderKey The sender key, when the key management algorithm is a static key agreement
     */
    public function decryptUsingKey(JWE &$jwe, JWK $jwk, int $recipient, ?JWK $senderKey = null): bool;

    /**
     * Decrypts the given recipient of the JWE using the given key set.
     *
     * A key that cannot be used, or that does not decrypt the recipient, does not abort the decryption: the next key
     * of the key set is tried and the reason of the failure is otherwise lost. A callable is accepted as an additional
     * argument to observe those failures; it is called with every discarded Throwable. That argument is not part of
     * the signature yet - it will be in 5.0.0 - and is read with func_num_args()/func_get_arg(5). An implementation
     * that does not read it still behaves correctly, it only loses the reason of the failures.
     *
     * @param JWK|null $jwk The key used to decrypt the token in case of success
     * @param JWK|null $senderKey The sender key, when the key management algorithm is a static key agreement
     */
    public function decryptUsingKeySet(
        JWE &$jwe,
        JWKSet $jwkset,
        int $recipient,
        ?JWK &$jwk = null,
        ?JWK $senderKey = null
    ): bool;
}
