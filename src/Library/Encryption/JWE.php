<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\JWT;
use Jose\Component\Core\Util\InheritanceChecker;
use Jose\Component\Core\Util\InternalCallChecker;
use Override;
use function array_key_exists;
use function count;
use function sprintf;

/**
 * An encrypted token, as returned by the builder or by a serializer.
 *
 * Every part of the token is given to the constructor but the plaintext, which is only known once a recipient has
 * been decrypted: withPayload() is reserved to the decrypter for that reason. The object is otherwise immutable and
 * must be treated as such, since the payload it exposes is the one the decrypter authenticated against the
 * ciphertext, the tag and the additional authenticated data. The class will be final and readonly in 5.0.0, where
 * the decrypted payload is given to the constructor.
 *
 * @final The class will be final and readonly in 5.0.0: build it with its constructor instead of extending it.
 */
class JWE implements JWT
{
    private ?string $payload = null;

    public function __construct(
        private readonly ?string $ciphertext,
        private readonly string $iv,
        private readonly string $tag,
        private readonly ?string $aad = null,
        private readonly array $sharedHeader = [],
        private readonly array $sharedProtectedHeader = [],
        private readonly ?string $encodedSharedProtectedHeader = null,
        private readonly array $recipients = []
    ) {
        InheritanceChecker::warnIfValueObjectExtended(static::class, self::class);
    }

    #[Override]
    public function getPayload(): ?string
    {
        return $this->payload;
    }

    /**
     * Set the payload. This method is immutable and a new object will be returned.
     *
     * The method is reserved to the JWE decrypter, the only object able to tell that the given plaintext is the one
     * protected by the token. Calling it from anywhere else is deprecated since 4.3.0 and raises a deprecation
     * notice: it lets any caller replace the payload of a decrypted token by an arbitrary value, and it will not be
     * possible in 5.0.0, where the payload is given to the constructor.
     *
     * @internal
     */
    public function withPayload(string $payload): self
    {
        InternalCallChecker::warnIfCalledFromOutside(
            self::class . '::withPayload',
            [self::class, JWEDecrypterInterface::class],
            'The payload of a JWE is set by the decrypter only. In 5.0.0 it is passed to the constructor of the JWE.'
        );

        $clone = clone $this;
        $clone->payload = $payload;

        return $clone;
    }

    /**
     * Returns the number of recipients associated with the JWS.
     */
    public function countRecipients(): int
    {
        return count($this->recipients);
    }

    /**
     * Returns true is the JWE has already been encrypted.
     */
    public function isEncrypted(): bool
    {
        return $this->getCiphertext() !== null;
    }

    /**
     * Returns the recipients associated with the JWS.
     *
     * @return Recipient[]
     */
    public function getRecipients(): array
    {
        return $this->recipients;
    }

    /**
     * Returns the recipient object at the given index.
     */
    public function getRecipient(int $id): Recipient
    {
        if (! isset($this->recipients[$id])) {
            throw new InvalidArgumentException('The recipient does not exist.');
        }

        return $this->recipients[$id];
    }

    /**
     * Returns the ciphertext. This method will return null is the JWE has not yet been encrypted.
     *
     * @return string|null The ciphertext
     */
    public function getCiphertext(): ?string
    {
        return $this->ciphertext;
    }

    /**
     * Returns the Additional Authentication Data if available.
     */
    public function getAAD(): ?string
    {
        return $this->aad;
    }

    /**
     * Returns the Initialization Vector if available.
     */
    public function getIV(): ?string
    {
        return $this->iv;
    }

    /**
     * Returns the tag if available.
     */
    public function getTag(): ?string
    {
        return $this->tag;
    }

    /**
     * Returns the encoded shared protected header.
     */
    public function getEncodedSharedProtectedHeader(): string
    {
        return $this->encodedSharedProtectedHeader ?? '';
    }

    /**
     * Returns the shared protected header.
     */
    public function getSharedProtectedHeader(): array
    {
        return $this->sharedProtectedHeader;
    }

    /**
     * Returns the shared protected header parameter identified by the given key. Throws an exception is the the
     * parameter is not available.
     *
     * @param string $key The key
     *
     * @return mixed|null
     */
    public function getSharedProtectedHeaderParameter(string $key)
    {
        if (! $this->hasSharedProtectedHeaderParameter($key)) {
            throw new InvalidHeaderParameterException(sprintf('The shared protected header "%s" does not exist.', $key));
        }

        return $this->sharedProtectedHeader[$key];
    }

    /**
     * Returns true if the shared protected header has the parameter identified by the given key.
     *
     * @param string $key The key
     */
    public function hasSharedProtectedHeaderParameter(string $key): bool
    {
        return array_key_exists($key, $this->sharedProtectedHeader);
    }

    /**
     * Returns the shared header.
     */
    public function getSharedHeader(): array
    {
        return $this->sharedHeader;
    }

    /**
     * Returns the shared header parameter identified by the given key. Throws an exception is the the parameter is not
     * available.
     *
     * @param string $key The key
     *
     * @return mixed|null
     */
    public function getSharedHeaderParameter(string $key)
    {
        if (! $this->hasSharedHeaderParameter($key)) {
            throw new InvalidHeaderParameterException(sprintf('The shared header "%s" does not exist.', $key));
        }

        return $this->sharedHeader[$key];
    }

    /**
     * Returns true if the shared header has the parameter identified by the given key.
     *
     * @param string $key The key
     */
    public function hasSharedHeaderParameter(string $key): bool
    {
        return array_key_exists($key, $this->sharedHeader);
    }

    /**
     * This method splits the JWE into a list of JWEs. It is only useful when the JWE contains more than one recipient
     * (JSON General Serialization).
     *
     * @return JWE[]
     */
    public function split(): array
    {
        $result = [];
        foreach ($this->recipients as $recipient) {
            $result[] = new self(
                $this->ciphertext,
                $this->iv,
                $this->tag,
                $this->aad,
                $this->sharedHeader,
                $this->sharedProtectedHeader,
                $this->encodedSharedProtectedHeader,
                [$recipient]
            );
        }

        return $result;
    }
}
