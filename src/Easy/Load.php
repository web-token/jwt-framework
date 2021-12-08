<?php

declare(strict_types=1);

namespace Jose\Easy;

class Load
{
    public static function jws(string $jws): Validate
    {
        return Validate::token($jws);
    }

    public static function jwe(string $jwe): Decrypt
    {
        return Decrypt::token($jwe);
    }
}
