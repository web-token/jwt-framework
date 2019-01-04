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
    public const JWS_BUILT_SUCCESS = 'jws_built_success';
    public const JWS_BUILT_FAILURE = 'jws_built_failure';
    public const JWS_VERIFICATION_SUCCESS = 'jws_verification_success';
    public const JWS_VERIFICATION_FAILURE = 'jws_verification_failure';
    public const JWS_LOADING_SUCCESS = 'jws_loading_success';
    public const JWS_LOADING_FAILURE = 'jws_loading_failure';

    public const JWE_BUILT_SUCCESS = 'jwe_built_success';
    public const JWE_BUILT_FAILURE = 'jwe_built_failure';
    public const JWE_DECRYPTION_SUCCESS = 'jwe_decryption_success';
    public const JWE_DECRYPTION_FAILURE = 'jwe_decryption_failure';
    public const JWE_LOADING_SUCCESS = 'jwe_loading_success';
    public const JWE_LOADING_FAILURE = 'jwe_loading_failure';

    public const NESTED_TOKEN_ISSUED = 'nested_token_issued';
    public const NESTED_TOKEN_LOADING_SUCCESS = 'nested_token_loading_success';
    public const NESTED_TOKEN_LOADING_FAILURE = 'nested_token_loading_failure';

    public const HEADER_CHECK_SUCCESS = 'header_check_success';
    public const HEADER_CHECK_FAILURE = 'header_check_failure';

    public const CLAIM_CHECK_SUCCESS = 'claim_check_success';
    public const CLAIM_CHECK_FAILURE = 'laim_check_failure';
}
