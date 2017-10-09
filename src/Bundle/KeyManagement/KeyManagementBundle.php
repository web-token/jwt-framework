<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\KeyManagement;

use Jose\Bundle\KeyManagement\DependencyInjection\Compiler\KeySetControllerCompilerPass;
use Jose\Bundle\KeyManagement\DependencyInjection\KeyManagementExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Class KeyManagementBundle.
 */
final class KeyManagementBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function getContainerExtension()
    {
        return new KeyManagementExtension();
    }

    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        $container->addCompilerPass(new KeySetControllerCompilerPass());
    }
}
