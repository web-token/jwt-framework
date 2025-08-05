<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase as BaseWebTestCase;

class WebTestCase extends BaseWebTestCase
{
    protected static function getKernelClass(): string
    {
        return AppKernel::class;
    }
}
