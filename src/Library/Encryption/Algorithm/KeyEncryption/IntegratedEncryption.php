<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;

/**
 * Integrated Encryption, the key management mode draft-ietf-jose-hpke-encrypt adds to JWE: the algorithm encrypts
 * the plaintext itself, without CEK and without content encryption algorithm.
 *
 * The JWE has no "enc" header parameter and exactly one recipient, whose encrypted key is produced by the algorithm;
 * the "alg" header parameter is in the protected header; the JWE Initialization Vector and the JWE Authentication
 * Tag are the empty octet sequence. The JWE builder and the JWE decrypter enforce these rules for every algorithm
 * implementing this interface. The additional authenticated data are computed from the encoded protected header
 * and the JWE AAD as for a content encryption algorithm (RFC 7516 section 5.1, step 14).
 */
interface IntegratedEncryption extends KeyEncryptionAlgorithm
{
    public const MODE_INTEGRATED = 'integrated';

    /**
     * Encrypts the payload for the recipient.
     *
     * @param JWK $recipientKey The public key of the recipient
     * @param JWK|null $senderKey The key authenticating the sender, when the algorithm supports one
     * @param string $payload The plaintext
     * @param string|null $aad The JWE AAD, only available with the JWE JSON Serialization
     * @param string $encodedProtectedHeader The protected header encoded in Base64Url
     * @param array<string, mixed> $completeHeader The complete header of the recipient
     */
    public function encryptPayload(
        JWK $recipientKey,
        ?JWK $senderKey,
        string $payload,
        ?string $aad,
        string $encodedProtectedHeader,
        array $completeHeader
    ): EncryptedPayload;

    /**
     * Decrypts the payload with the key of the recipient.
     *
     * @param JWK $recipientKey The private key of the recipient
     * @param JWK|null $senderKey The key authenticating the sender, when the algorithm supports one
     * @param string $encryptedKey The JWE Encrypted Key
     * @param string $ciphertext The JWE Ciphertext
     * @param string|null $aad The JWE AAD, only available with the JWE JSON Serialization
     * @param string $encodedProtectedHeader The protected header encoded in Base64Url
     * @param array<string, mixed> $completeHeader The complete header of the recipient
     */
    public function decryptPayload(
        JWK $recipientKey,
        ?JWK $senderKey,
        string $encryptedKey,
        string $ciphertext,
        ?string $aad,
        string $encodedProtectedHeader,
        array $completeHeader
    ): string;
}
