<?php

declare(strict_types=1);

namespace Jose\Easy;

class Build
{
    public static function jws(): JWSBuilder
    {
        return new JWSBuilder();
    }

    public static function jwe(): JWEBuilder
    {
        return new JWEBuilder();
    }
}
