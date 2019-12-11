<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Easy\Tests\Algorithm;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

/**
 * Class ExceptionTestAlgorithm - DO NOT USE.
 */
final class ExceptionTestAlgorithm implements SignatureAlgorithm
{
    public function __construct()
    {
        throw new \BadFunctionCallException('exception example class');
    }

    /**
     * @inheritDoc
     */
    public function name(): string
    {
        throw new \BadFunctionCallException('should not be called');
    }

    /**
     * @inheritDoc
     */
    public function allowedKeyTypes(): array
    {
        throw new \BadFunctionCallException('should not be called');
    }

    /**
     * @inheritDoc
     */
    public function sign(JWK $key, string $input): string
    {
        throw new \BadFunctionCallException('should not be called');
    }

    /**
     * @inheritDoc
     */
    public function verify(JWK $key, string $input, string $signature): bool
    {
        throw new \BadFunctionCallException('should not be called');
    }
}
