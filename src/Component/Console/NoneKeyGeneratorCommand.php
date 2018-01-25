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

namespace Jose\Component\Console;

use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Class NoneKeyGeneratorCommand.
 */
final class NoneKeyGeneratorCommand extends GeneratorCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        parent::configure();
        $this
            ->setName('key:generate:none')
            ->setDescription('Generate a none key (JWK format). This key type is only supposed to be used with the "none" algorithm.');
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createNoneKey($args);
        $this->prepareJsonOutput($input, $output, $jwk);
    }
}
