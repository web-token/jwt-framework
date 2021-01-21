<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Console;

use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class NoneKeyGeneratorCommand extends GeneratorCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('key:generate:none')
            ->setDescription('Generate a none key (JWK format). This key type is only supposed to be used with the "none" algorithm.')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createNoneKey($args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return 0;
    }
}
