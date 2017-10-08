<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests\Stub;

use Jose\Component\Core\JWTInterface;

/**
 * Class Token.
 */
final class Token implements JWTInterface
{
    /**
     * @var null|string
     */
    private $payload;

    /**
     * Token constructor.
     *
     * @param null|string $payload
     */
    private function __construct(?string $payload)
    {
        $this->payload = $payload;
    }

    /**
     * @param null|string $payload
     *
     * @return Token
     */
    public static function create(?string $payload): Token
    {
        return new self($payload);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): ?string
    {
        return $this->payload;
    }
}
