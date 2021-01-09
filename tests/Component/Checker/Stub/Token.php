<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\Checker\Stub;

use Jose\Component\Core\JWT;

class Token implements JWT
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

    public function __construct(?string $payload, array $protectedHeader, array $unprotectedHeader)
    {
        $this->payload = $payload;
        $this->protectedHeader = $protectedHeader;
        $this->unprotectedHeader = $unprotectedHeader;
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
