<?php

declare(strict_types=1);

use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource\CertificateFile;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource\JWK;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource\JWKSet;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource\KeyFile;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource\P12;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource\Secret;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource\Values;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource\X5C;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->public()
        ->autoconfigure()
        ->autowire();

    $container->set(KeyFile::class);
    $container->set(P12::class);
    $container->set(CertificateFile::class);
    $container->set(Values::class);
    $container->set(Secret::class);
    $container->set(JWK::class);
    $container->set(X5C::class);
    $container->set(JWKSet::class);
};
