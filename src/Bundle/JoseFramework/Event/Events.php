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

namespace Jose\Bundle\JoseFramework\Event;

final class Events
{
    public const JWS_BUILT = 'jws_built';
    public const JWS_LOADING_SUCCESS = 'jws_loading_success';
    public const JWS_LOADING_FAILURE = 'jws_loading_failure';

    public const JWE_BUILT = 'jwe_built';
    public const JWE_LOADING_SUCCESS = 'jwe_loading_success';
    public const JWE_LOADING_FAILURE = 'jwe_loading_failure';

    public const NESTED_TOKEN_ISSUED = 'nested_token_issued';
    public const NESTED_TOKEN_LOADING_SUCCESS = 'nested_token_loading_success';
    public const NESTED_TOKEN_LOADING_FAILURE = 'nested_token_loading_failure';
}
