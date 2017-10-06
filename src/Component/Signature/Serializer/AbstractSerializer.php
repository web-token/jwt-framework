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

namespace Jose\Component\Signature\Serializer;

/**
 * Class AbstractSerializer.
 */
abstract class AbstractSerializer implements JWSSerializerInterface
{
    /**
     * @param array $protectedHeaders
     *
     * @return bool
     */
    protected function isPayloadEncoded(array $protectedHeaders): bool
    {
        return !array_key_exists('b64', $protectedHeaders) || true === $protectedHeaders['b64'];
    }
}
