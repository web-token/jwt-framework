<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\Algorithm;

class FooAlgorithm implements Algorithm
{
    public function name(): string
    {
        return 'foo';
    }

    public function allowedKeyTypes(): array
    {
        return ['FOO'];
    }
}
