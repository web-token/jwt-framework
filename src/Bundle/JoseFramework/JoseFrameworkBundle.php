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

namespace Jose\Bundle\JoseFramework;

use Jose\Bundle\JoseFramework\DependencyInjection\JoseFrameworkExtension;
use Jose\Bundle\JoseFramework\DependencyInjection\Source;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Class JoseFrameworkBundle.
 */
class JoseFrameworkBundle extends Bundle
{
    /**
     * @var Source\Source[]
     */
    private $sources = [];

    /**
     * JoseFrameworkBundle constructor.
     */
    public function __construct()
    {
        foreach ($this->getSources() as $source) {
            $this->sources[$source->name()] = $source;
        }
    }

    public function getContainerExtension()
    {
        return new JoseFrameworkExtension('jose', $this->sources);
    }

    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        foreach ($this->sources as $source) {
            if ($source instanceof Source\SourceWithCompilerPasses) {
                $compilerPasses = $source->getCompilerPasses();
                foreach ($compilerPasses as $compilerPass) {
                    $container->addCompilerPass($compilerPass);
                }
            }
        }
    }

    /**
     * @return Source\Source[]
     */
    private function getSources(): array
    {
        return [
            new Source\Core\CoreSource(),
            new Source\Checker\CheckerSource(),
            new Source\Console\ConsoleSource(),
            new Source\Signature\SignatureSource(),
            new Source\Encryption\EncryptionSource(),
            new Source\Encryption\NestedToken(),
            new Source\KeyManagement\KeyManagementSource(),
        ];
    }
}
