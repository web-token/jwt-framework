<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework;

use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\EventDispatcherAliasCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\SymfonySerializerCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\JoseFrameworkExtension;
use Jose\Bundle\JoseFramework\DependencyInjection\Source;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Checker\CheckerSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Console\ConsoleSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Core\CoreSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Encryption\EncryptionSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\KeyManagementSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\NestedToken\NestedToken;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Signature\SignatureSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceWithCompilerPasses;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

final class JoseFrameworkBundle extends Bundle
{
    /**
     * @var Source\Source[]
     */
    private array $sources = [];

    public function __construct()
    {
        foreach ($this->getSources() as $source) {
            $this->sources[$source->name()] = $source;
        }
    }

    public function getContainerExtension(): ExtensionInterface
    {
        return new JoseFrameworkExtension('jose', $this->sources);
    }

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);
        foreach ($this->sources as $source) {
            if ($source instanceof SourceWithCompilerPasses) {
                $compilerPasses = $source->getCompilerPasses();
                foreach ($compilerPasses as $compilerPass) {
                    $container->addCompilerPass($compilerPass, PassConfig::TYPE_BEFORE_OPTIMIZATION, 0);
                }
            }
        }

        $container->addCompilerPass(new EventDispatcherAliasCompilerPass(), PassConfig::TYPE_BEFORE_OPTIMIZATION, 0);
        $container->addCompilerPass(new SymfonySerializerCompilerPass(), PassConfig::TYPE_BEFORE_OPTIMIZATION, 10);
    }

    /**
     * @return Source\Source[]
     */
    private function getSources(): iterable
    {
        return [
            new CoreSource(),
            new CheckerSource(),
            new ConsoleSource(),
            new SignatureSource(),
            new EncryptionSource(),
            new NestedToken(),
            new KeyManagementSource(),
        ];
    }
}
