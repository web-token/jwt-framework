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

namespace Jose\Bundle\JoseFramework\Controller;

use Symfony\Component\HttpFoundation\Response;

class JWKSetController
{
    /**
     * @var string
     */
    private $jwkset;

    public function __construct(string $jwkset)
    {
        $this->jwkset = $jwkset;
    }

    public function __invoke(): Response
    {
        return new Response(
            $this->jwkset,
            Response::HTTP_OK,
            [
                'Content-Type' => 'application/jwk-set+json; charset=UTF-8',
            ]
        );
    }
}
