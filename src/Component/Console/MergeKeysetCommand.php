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

use InvalidArgumentException;
use function is_array;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class MergeKeysetCommand extends ObjectOutputCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('keyset:merge')
            ->setDescription('Merge several key sets into one.')
            ->setHelp('This command merges several key sets into one. It is very useful when you generate e.g. RSA, EC and OKP keys and you want only one key set to rule them all.')
            ->addArgument('jwksets', InputArgument::REQUIRED | InputArgument::IS_ARRAY, 'The JWKSet objects')
        ;
    }

    /**
     * @throws InvalidArgumentException if the JWKSet is invalid
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        /** @var string[] $keySets */
        $keySets = $input->getArgument('jwksets');
        $newJwkset = new JWKSet([]);
        foreach ($keySets as $keySet) {
            $json = JsonConverter::decode($keySet);
            if (!is_array($json)) {
                throw new InvalidArgumentException('The argument must be a valid JWKSet.');
            }
            $jwkset = JWKSet::createFromKeyData($json);
            foreach ($jwkset->all() as $jwk) {
                $newJwkset = $newJwkset->with($jwk);
            }
        }
        $this->prepareJsonOutput($input, $output, $newJwkset);

        return 0;
    }
}
