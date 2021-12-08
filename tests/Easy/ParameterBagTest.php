<?php

declare(strict_types=1);

namespace Jose\Tests\Easy;

use Jose\Easy\ParameterBag;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class ParameterBagTest extends TestCase
{
    /**
     * @test
     */
    public function basicCalls(): void
    {
        $bag = new ParameterBag();
        $bag->iss('iss');
        $bag->alg('alg');
        $bag->aud(['aud']);

        static::assertSame(['aud'], $bag->aud());
        static::assertSame('iss', $bag->get('iss'));
        static::assertSame('alg', $bag->get('alg'));
    }
}
