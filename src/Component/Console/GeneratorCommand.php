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

use Base64Url\Base64Url;
use InvalidArgumentException;
use function is_bool;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

abstract class GeneratorCommand extends ObjectOutputCommand
{
    public function isEnabled()
    {
        return class_exists(JWKFactory::class);
    }

    protected function configure(): void
    {
        parent::configure();
        $this
            ->addOption('use', 'u', InputOption::VALUE_OPTIONAL, 'Usage of the key. Must be either "sig" or "enc".')
            ->addOption('alg', 'a', InputOption::VALUE_OPTIONAL, 'Algorithm for the key.')
            ->addOption('random_id', null, InputOption::VALUE_NONE, 'If this option is set, a random key ID (kid) will be generated.')
        ;
    }

    /**
     * @throws InvalidArgumentException if the option "random_id" is not a valid
     */
    protected function getOptions(InputInterface $input): array
    {
        $args = [];
        $useRandomId = $input->getOption('random_id');
        if (!is_bool($useRandomId)) {
            throw new InvalidArgumentException('Invalid value for option "random_id"');
        }
        if ($useRandomId) {
            $args['kid'] = $this->generateKeyID();
        }
        foreach (['use', 'alg'] as $key) {
            $value = $input->getOption($key);
            if (null !== $value) {
                $args[$key] = $value;
            }
        }

        return $args;
    }

    private function generateKeyID(): string
    {
        return Base64Url::encode(random_bytes(32));
    }
}
