<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;

interface KeyWrapping extends KeyEncryptionAlgorithm
{
    /**
     * Encrypt the CEK.
     *
     * @param JWK $key The key used to wrap the CEK
     * @param string $cek The CEK to encrypt
     * @param array<string, mixed> $completeHeader The complete header of the JWT
     * @param array<string, mixed> $additionalHeader The complete header of the JWT
     *
     * BC NOTE: in 5.0, this method will return a "WrappedKey" object - the wrapped CEK and the header parameters to
     * add to the token - and the "array &$additionalHeader" output parameter will be removed. The change cannot be
     * made now without breaking every implementation of this interface. Implementations are encouraged to prepare
     * for it: the object is already available as
     * Jose\Component\Encryption\Algorithm\KeyEncryption\WrappedKey.
     */
    public function wrapKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string;

    /**
     * Decrypt de CEK.
     *
     * @param JWK $key The key used to wrap the CEK
     * @param string $encrypted_cek The CEK to decrypt
     * @param array<string, mixed> $completeHeader The complete header of the JWT
     *
     * BC NOTE: since 4.2, the JWEDecrypter calls this method with an additional argument
     * "int $encryptionKeyLength": the size (in bits) of the key expected by the content encryption algorithm,
     * as returned by ContentEncryptionAlgorithm::getCEKSize(). As it is not declared yet, implementations that
     * need it can read it with func_num_args()/func_get_arg(3). It will be declared and required in 5.0.
     */
    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string;
}
