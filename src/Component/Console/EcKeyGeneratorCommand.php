<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use InvalidArgumentException;
use function is_string;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class EcKeyGeneratorCommand extends GeneratorCommand
{
    protected static $defaultName = 'key:generate:ec';

    protected function configure(): void
    {
        parent::configure();
        $this->setDescription('Generate an EC key (JWK format)')
            ->addArgument('curve', InputArgument::REQUIRED, 'Curve of the key.')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $curve = $input->getArgument('curve');
        if (! is_string($curve)) {
            throw new InvalidArgumentException('Invalid curve');
        }
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createECKey($curve, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return 0;
    }
}
