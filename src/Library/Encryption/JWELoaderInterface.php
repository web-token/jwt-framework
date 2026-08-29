<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Serializer\JWESerializerManager;

/**
 * Loads a serialized JWE, checks its header and decrypts it.
 *
 * The interface is implemented by JWELoader and by every object that decorates it. Decoration is the supported way of
 * plugging behaviour into the loader: JWELoader is annotated as final and will be final in 5.0.0.
 *
 * The interface only declares the methods that will survive 5.0.0. "loadAndDecryptWithKey()" and
 * "loadAndDecryptWithKeySet()", deprecated since 4.3.0 because they write the index of the decrypted recipient into
 * a variable of the caller, are still available on JWELoader and on the objects of this package that decorate it,
 * but they are not part of the contract.
 */
interface JWELoaderInterface
{
    /**
     * Returns the decrypter associated to the loader.
     */
    public function getJweDecrypter(): JWEDecrypterInterface;

    /**
     * Returns the header checker manager associated to the loader, if any.
     */
    public function getHeaderCheckerManager(): ?HeaderCheckerManagerInterface;

    /**
     * Returns the serializer manager associated to the loader.
     */
    public function getSerializerManager(): JWESerializerManager;

    /**
     * Loads and decrypts the token using the given key or key set. The decrypted JWE, the index of the decrypted
     * recipient and the key that decrypted it are carried by the returned result, otherwise an exception is thrown.
     *
     * @param JWK|JWKSet $keys The recipient will be decrypted using that key or the keys in that key set
     */
    public function loadAndDecrypt(string $token, JWK|JWKSet $keys): LoadingResult;
}
