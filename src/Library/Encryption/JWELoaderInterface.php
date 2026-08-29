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
     * Loads and decrypts the token using the given key. It returns a JWE and populates the $recipient variable in case
     * of success, otherwise an exception is thrown.
     */
    public function loadAndDecryptWithKey(string $token, JWK $key, ?int &$recipient): JWE;

    /**
     * Loads and decrypts the token using the given key set. It returns a JWE and populates the $recipient variable in
     * case of success, otherwise an exception is thrown.
     */
    public function loadAndDecryptWithKeySet(string $token, JWKSet $keyset, ?int &$recipient): JWE;
}
