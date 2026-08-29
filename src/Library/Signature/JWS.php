<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\JWT;
use Jose\Component\Core\Util\InternalCallChecker;
use Jose\Component\Signature\Serializer\JWSSerializer;
use Override;
use function count;

/**
 * A signed token, as returned by the builder or by a serializer.
 *
 * The object is assembled incrementally: the payload is given to the constructor and the signatures are appended by
 * addSignature(), which is reserved to the builder and to the serializers. It is otherwise immutable and must be
 * treated as such: a token returned by a loader carries signatures that have been verified against its payload, and
 * nothing else is allowed to append to that list. The class will be final and readonly in 5.0.0, where the
 * signatures are given to the constructor.
 *
 * @see \Jose\Tests\Component\Signature\JWSTest
 */
class JWS implements JWT
{
    /**
     * @var Signature[]
     */
    private array $signatures = [];

    public function __construct(
        private readonly ?string $payload,
        private readonly ?string $encodedPayload = null,
        private readonly bool $isPayloadDetached = false
    ) {
    }

    #[Override]
    public function getPayload(): ?string
    {
        return $this->payload;
    }

    /**
     * Returns true if the payload is detached.
     */
    public function isPayloadDetached(): bool
    {
        return $this->isPayloadDetached;
    }

    /**
     * Returns the Base64Url encoded payload. If the payload is detached, this method returns null.
     */
    public function getEncodedPayload(): ?string
    {
        if ($this->isPayloadDetached()) {
            return null;
        }

        return $this->encodedPayload;
    }

    /**
     * Returns the signatures associated with the JWS.
     *
     * @return Signature[]
     */
    public function getSignatures(): array
    {
        return $this->signatures;
    }

    /**
     * Returns the signature at the given index.
     */
    public function getSignature(int $id): Signature
    {
        if (isset($this->signatures[$id])) {
            return $this->signatures[$id];
        }

        throw new InvalidArgumentException('The signature does not exist.');
    }

    /**
     * This method adds a signature to the JWS object. Its returns a new JWS object.
     *
     * The method is reserved to the JWS builder and to the JWS serializers, the only objects that assemble a token
     * from its parts. Calling it from anywhere else is deprecated since 4.3.0 and raises a deprecation notice: it
     * defeats the immutability of the object and it will not be possible in 5.0.0, where the signatures are given
     * to the constructor.
     *
     * @internal
     *
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $header
     */
    public function addSignature(
        string $signature,
        array $protectedHeader,
        ?string $encodedProtectedHeader,
        array $header = []
    ): self {
        InternalCallChecker::warnIfCalledFromOutside(
            self::class . '::addSignature',
            [self::class, JWSBuilderInterface::class, JWSSerializer::class],
            'A JWS is assembled by the builder and by the serializers only. In 5.0.0 the signatures are passed to '
            . 'the constructor of the JWS.'
        );

        $jws = clone $this;
        $jws->signatures[] = new Signature($signature, $protectedHeader, $encodedProtectedHeader, $header);

        return $jws;
    }

    /**
     * Returns the number of signature associated with the JWS.
     */
    public function countSignatures(): int
    {
        return count($this->signatures);
    }

    /**
     * This method splits the JWS into a list of JWSs. It is only useful when the JWS contains more than one signature
     * (JSON General Serialization).
     *
     * @return JWS[]
     */
    public function split(): array
    {
        $result = [];
        foreach ($this->signatures as $signature) {
            $jws = new self($this->payload, $this->encodedPayload, $this->isPayloadDetached);
            $jws = $jws->addSignature(
                $signature->getSignature(),
                $signature->getProtectedHeader(),
                $signature->getEncodedProtectedHeader(),
                $signature->getHeader()
            );

            $result[] = $jws;
        }

        return $result;
    }
}
