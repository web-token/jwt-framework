<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use InvalidArgumentException;
use function is_int;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class RsaKeysetGeneratorCommand extends GeneratorCommand
{
    protected static $defaultName = 'keyset:generate:rsa';

    protected function configure(): void
    {
        parent::configure();
        $this->setDescription('Generate a key set with RSA keys (JWK format)')
            ->addArgument('quantity', InputArgument::REQUIRED, 'Quantity of keys in the key set.')
            ->addArgument('size', InputArgument::REQUIRED, 'Key size.')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $quantity = $input->getArgument('quantity');
        if (! is_int($quantity)) {
            $quantity = 1;
        }
        $size = $input->getArgument('size');
        if (! is_int($size)) {
            $size = 1;
        }
        if ($quantity < 1) {
            throw new InvalidArgumentException('Invalid quantity');
        }
        if ($size < 1) {
            throw new InvalidArgumentException('Invalid size');
        }

        $keyset = new JWKSet([]);
        for ($i = 0; $i < $quantity; ++$i) {
            $args = $this->getOptions($input);
            $keyset = $keyset->with(JWKFactory::createRSAKey($size, $args));
        }
        $this->prepareJsonOutput($input, $output, $keyset);

        return 0;
    }
}
