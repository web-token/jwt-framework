<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase as BaseKernelTestCase;

class KernelTestCase extends BaseKernelTestCase
{
    protected static function getKernelClass(): string
    {
        return AppKernel::class;
    }
}
