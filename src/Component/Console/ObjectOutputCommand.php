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

use Jose\Component\Core\Util\JsonConverter;
use JsonSerializable;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

abstract class ObjectOutputCommand extends Command
{
    protected function prepareJsonOutput(InputInterface $input, OutputInterface $output, JsonSerializable $json): void
    {
        $data = JsonConverter::encode($json);
        $output->write($data);
    }
}
