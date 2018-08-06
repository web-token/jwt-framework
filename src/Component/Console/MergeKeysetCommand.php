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

use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\JWKSet;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class MergeKeysetCommand extends ObjectOutputCommand
{
    /**
     * KeyAnalyzerCommand constructor.
     */
    public function __construct(JsonConverter $jsonConverter, string $name = null)
    {
        parent::__construct($jsonConverter, $name);
    }

    protected function configure()
    {
        parent::configure();
        $this
            ->setName('keyset:merge')
            ->setDescription('Merge several key sets into one.')
            ->setHelp('This command merges several key sets into one. It is very useful when you generate e.g. RSA, EC and OKP keys and you want only one key set to rule them all.')
            ->addArgument('jwksets', InputArgument::REQUIRED | InputArgument::IS_ARRAY, 'The JWKSet objects');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $keySets = $input->getArgument('jwksets');
        $newJwkset = JWKSet::createFromKeys([]);
        foreach ($keySets as $keySet) {
            $json = $this->jsonConverter->decode($keySet);
            if (!\is_array($json)) {
                throw new \InvalidArgumentException('The argument must be a valid JWKSet.');
            }
            $jwkset = JWKSet::createFromKeyData($json);
            foreach ($jwkset->all() as $jwk) {
                $newJwkset = $newJwkset->with($jwk);
            }
        }
        $this->prepareJsonOutput($input, $output, $newJwkset);
    }
}
