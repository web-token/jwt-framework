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

namespace Jose\Component\Core;

/**
 * Interface JWT.
 */
interface JWT
{
    /**
     * Returns the payload of the JWT.
     *
     * @return string|null
     */
    public function getPayload(): ?string;
}
