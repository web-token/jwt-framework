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

namespace Jose\Component\Checker;

use Jose\Component\Core\JWT;

/**
 * Interface TokenTypeSupport.
 */
interface TokenTypeSupport
{
    /**
     * @param JWT $jwt
     * @param int          $component
     * @param array        $protectedHeader
     * @param array        $unprotectedHeader
     */
    public function retrieveTokenHeaders(JWT $jwt, int $component, array &$protectedHeader, array &$unprotectedHeader): void;

    /**
     * @param JWT $jwt
     *
     * @return bool
     */
    public function supports(JWT $jwt): bool;
}
