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

namespace Jose\Bundle\JoseFramework\EnvVarProcessor;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Symfony\Component\DependencyInjection\EnvVarProcessorInterface;

class KeyEnvVarProcessor implements EnvVarProcessorInterface
{
    public function getEnv($prefix, $name, \Closure $getEnv)
    {
        $env = $getEnv($name);
        switch ($prefix) {
            case 'jwk':
                return JWK::createFromJson($env);
            case 'jwkset':
                return JWKSet::createFromJson($env);
            default:
                throw new \RuntimeException(\sprintf('Unsupported prefix "%s".', $prefix));
        }
    }

    public static function getProvidedTypes()
    {
        return [
            'jwk' => 'string',
            'jwkset' => 'string',
        ];
    }
}
