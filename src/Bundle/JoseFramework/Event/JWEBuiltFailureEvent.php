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

namespace Jose\Bundle\JoseFramework\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class JWEBuiltFailureEvent extends Event
{
    /**
     * @var Throwable
     */
    private $throwable;

    /**
     * @var null|string
     */
    private $payload;

    /**
     * @var array
     */
    private $recipients;

    /**
     * @var array
     */
    private $sharedProtectedHeader;

    /**
     * @var array
     */
    private $sharedHeader;

    /**
     * @var null|string
     */
    private $aad;

    public function __construct(?string $payload, array $recipients, array $sharedProtectedHeader, array $sharedHeader, ?string $aad, Throwable $throwable)
    {
        $this->throwable = $throwable;
        $this->payload = $payload;
        $this->recipients = $recipients;
        $this->sharedProtectedHeader = $sharedProtectedHeader;
        $this->sharedHeader = $sharedHeader;
        $this->aad = $aad;
    }

    public function getPayload(): ?string
    {
        return $this->payload;
    }

    public function getRecipients(): array
    {
        return $this->recipients;
    }

    public function getSharedProtectedHeader(): array
    {
        return $this->sharedProtectedHeader;
    }

    public function getSharedHeader(): array
    {
        return $this->sharedHeader;
    }

    public function getAad(): ?string
    {
        return $this->aad;
    }

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
