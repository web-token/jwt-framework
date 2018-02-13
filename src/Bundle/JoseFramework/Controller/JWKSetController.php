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

namespace Jose\Bundle\JoseFramework\Controller;

use Symfony\Component\HttpFoundation\Response;

/**
 * Class JWKSetController.
 */
final class JWKSetController
{
    /**
     * @var string
     */
    private $jwkset;

    /**
     * @var int
     */
    private $maxAge;

    /**
     * JWKSetController constructor.
     *
     * @param string $jwkset
     * @param int    $maxAge
     */
    public function __construct(string $jwkset, int $maxAge)
    {
        $this->jwkset = $jwkset;
        $this->maxAge = $maxAge;
    }

    /**
     * @return Response
     */
    public function getAction(): Response
    {
        return new Response(
            $this->jwkset,
            Response::HTTP_OK,
            [
                'Content-Type'  => 'application/jwk-set+json; charset=UTF-8',
                'Cache-Control' => sprintf('public, max-age=%d, must-revalidate, no-transform', $this->maxAge),
            ]
        );
    }
}
