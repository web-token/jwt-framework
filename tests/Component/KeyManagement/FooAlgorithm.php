<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\Algorithm;
use Override;

class FooAlgorithm implements Algorithm
{
    #[Override]
    public function name(): string
    {
        return 'foo';
    }

    #[Override]
    public function allowedKeyTypes(): array
    {
        return ['FOO'];
    }
}
