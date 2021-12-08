<?php

declare(strict_types=1);

namespace Jose\Easy;

final class JWT
{
    public ParameterBag $claims;

    public ParameterBag $header;

    public function __construct()
    {
        $this->claims = new ParameterBag();
        $this->header = new ParameterBag();
    }
}
