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
use function is_string;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatterStyle;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class KeyAnalyzerCommand extends Command
{
    /**
     * @var KeyAnalyzerManager
     */
    private $analyzerManager;

    public function __construct(KeyAnalyzerManager $keysetAnalyzerManager, string $name = null)
    {
        parent::__construct($name);
        $this->analyzerManager = $keysetAnalyzerManager;
    }

    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('key:analyze')
            ->setDescription('JWK quality analyzer.')
            ->setHelp('This command will analyze a JWK object and find security issues.')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The JWK object')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->getFormatter()->setStyle('success', new OutputFormatterStyle('white', 'green'));
        $output->getFormatter()->setStyle('high', new OutputFormatterStyle('white', 'red', ['bold']));
        $output->getFormatter()->setStyle('medium', new OutputFormatterStyle('yellow'));
        $output->getFormatter()->setStyle('low', new OutputFormatterStyle('blue'));
        $jwk = $this->getKey($input);

        $result = $this->analyzerManager->analyze($jwk);
        if (0 === $result->count()) {
            $output->writeln('<success>All good! No issue found.</success>');
        } else {
            foreach ($result->all() as $message) {
                $output->writeln('<'.$message->getSeverity().'>* '.$message->getMessage().'</'.$message->getSeverity().'>');
            }
        }

        return 0;
    }

    /**
     * @throws InvalidArgumentException if the key is invalid
     */
    private function getKey(InputInterface $input): JWK
    {
        $jwk = $input->getArgument('jwk');
        if (!is_string($jwk)) {
            throw new InvalidArgumentException('Invalid JWK');
        }
        $json = JsonConverter::decode($jwk);
        if (!is_array($json)) {
            throw new InvalidArgumentException('Invalid JWK.');
        }

        return new JWK($json);
    }
}
