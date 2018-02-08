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
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Class AbstractObjectOutputCommand.
 */
abstract class ObjectOutputCommand extends Command
{
    /**
     * @var JsonConverter
     */
    protected $jsonConverter;

    /**
     * AbstractGeneratorCommand constructor.
     *
     * @param JsonConverter $jsonConverter
     * @param string|null   $name
     */
    public function __construct(JsonConverter $jsonConverter, string $name = null)
    {
        $this->jsonConverter = $jsonConverter;
        parent::__construct($name);
    }

    /**
     * Configures the current command.
     */
    protected function configure()
    {
        $this
            ->addOption('out', 'o', InputOption::VALUE_OPTIONAL, 'File where to save the key. Must be a valid and writable file name.');
    }

    /**
     * @param InputInterface    $input
     * @param OutputInterface   $output
     * @param \JsonSerializable $json
     */
    protected function prepareJsonOutput(InputInterface $input, OutputInterface $output, \JsonSerializable $json)
    {
        $json = $this->jsonConverter->encode($json);
        $this->prepareOutput($input, $output, $json);
    }

    /**
     * @param InputInterface  $input
     * @param OutputInterface $output
     * @param string          $data
     */
    protected function prepareOutput(InputInterface $input, OutputInterface $output, string $data)
    {
        $file = $input->getOption('out');
        if (null !== $file) {
            file_put_contents($file, $data, LOCK_EX);
        } else {
            $output->write($data);
        }
    }
}
