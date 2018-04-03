<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature;

use Jose\Component\Core\JWT;

class JWS implements JWT
{
    /**
     * @var bool
     */
    private $isPayloadDetached = false;

    /**
     * @var string|null
     */
    private $encodedPayload = null;

    /**
     * @var Signature[]
     */
    private $signatures = [];

    /**
     * @var string|null
     */
    private $payload = null;

    /**
     * JWS constructor.
     *
     * @param string|null $payload
     * @param string|null $encodedPayload
     * @param bool        $isPayloadDetached
     */
    private function __construct(?string $payload, ?string $encodedPayload = null, bool $isPayloadDetached = false)
    {
        $this->payload = $payload;
        $this->encodedPayload = $encodedPayload;
        $this->isPayloadDetached = $isPayloadDetached;
    }

    /**
     * Creates a JWS object.
     *
     * @param string|null $payload
     * @param string|null $encodedPayload
     * @param bool        $isPayloadDetached
     *
     * @return JWS
     */
    public static function create(?string $payload, ?string $encodedPayload = null, bool $isPayloadDetached = false): self
    {
        return new self($payload, $encodedPayload, $isPayloadDetached);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): ?string
    {
        return $this->payload;
    }

    /**
     * Returns true if the payload is detached.
     *
     * @return bool
     */
    public function isPayloadDetached(): bool
    {
        return $this->isPayloadDetached;
    }

    /**
     * Returns the Base64Url encoded payload.
     * If the payload is detached, this method returns null.
     *
     * @return string|null
     */
    public function getEncodedPayload(): ?string
    {
        if (true === $this->isPayloadDetached()) {
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
     *
     * @param int $id
     *
     * @return Signature
     */
    public function getSignature(int $id): Signature
    {
        if (isset($this->signatures[$id])) {
            return $this->signatures[$id];
        }

        throw new \InvalidArgumentException('The signature does not exist.');
    }

    /**
     * This method adds a signature to the JWS object.
     * Its returns a new JWS object.
     *
     * @internal
     *
     * @param string      $signature
     * @param array       $protectedHeader
     * @param string|null $encodedProtectedHeader
     * @param array       $header
     *
     * @return JWS
     */
    public function addSignature(string $signature, array $protectedHeader, ?string $encodedProtectedHeader, array $header = []): self
    {
        $jws = clone $this;
        $jws->signatures[] = Signature::create($signature, $protectedHeader, $encodedProtectedHeader, $header);

        return $jws;
    }

    /**
     * Returns the number of signature associated with the JWS.
     *
     * @return int
     */
    public function countSignatures(): int
    {
        return count($this->signatures);
    }

    /**
     * This method splits the JWS into a list of JWSs.
     * It is only useful when the JWS contains more than one signature (JSON General Serialization).
     *
     * @return JWS[]
     */
    public function split(): array
    {
        $result = [];
        foreach ($this->signatures as $signature) {
             $jws = JWS::create(
                $this->payload,
                $this->encodedPayload,
                $this->isPayloadDetached
            );
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
