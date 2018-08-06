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

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class OctKeysetGeneratorCommand extends GeneratorCommand
{
    protected function configure()
    {
        parent::configure();
        $this
            ->setName('keyset:generate:oct')
            ->setDescription('Generate a key set with octet keys (JWK format)')
            ->addArgument('quantity', InputArgument::REQUIRED, 'Quantity of keys in the key set.')
            ->addArgument('size', InputArgument::REQUIRED, 'Key size.');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $quantity = \intval($input->getArgument('quantity'));
        $size = \intval($input->getArgument('size'));

        $keyset = JWKSet::createFromKeys([]);
        for ($i = 0; $i < $quantity; ++$i) {
            $args = $this->getOptions($input);
            $keyset = $keyset->with(JWKFactory::createOctKey($size, $args));
        }
        $this->prepareJsonOutput($input, $output, $keyset);
    }
}
