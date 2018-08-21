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

namespace Jose\Component\Checker\Tests\Stub;

use Jose\Component\Core\JWT;

class OtherToken implements JWT
{
    /**
     * @var null|string
     */
    private $payload;

    /**
     * @var array
     */
    private $protectedHeader;

    /**
     * @var array
     */
    private $unprotectedHeader;

    /**
     * Token constructor.
     */
    private function __construct(?string $payload, array $protectedHeader, array $unprotectedHeader)
    {
        $this->payload = $payload;
        $this->protectedHeader = $protectedHeader;
        $this->unprotectedHeader = $unprotectedHeader;
    }

    public static function create(?string $payload, array $protectedHeader = [], array $unprotectedHeader = []): self
    {
        return new self($payload, $protectedHeader, $unprotectedHeader);
    }

    public function getPayload(): ?string
    {
        return $this->payload;
    }

    public function getProtectedHeader(): array
    {
        return $this->protectedHeader;
    }

    public function getUnprotectedHeader(): array
    {
        return $this->unprotectedHeader;
    }
}
