<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use InvalidArgumentException;
use function is_array;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class OctKeysetGeneratorCommand extends GeneratorCommand
{
    protected static $defaultName = 'keyset:generate:oct';

    protected function configure(): void
    {
        parent::configure();
        $this->setDescription('Generate a key set with octet keys (JWK format)')
            ->addArgument('quantity', InputArgument::REQUIRED, 'Quantity of keys in the key set.')
            ->addArgument('size', InputArgument::REQUIRED, 'Key size.')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $quantity = $input->getArgument('quantity');
        if ($quantity === null) {
            $quantity = 1;
        } elseif (is_array($quantity)) {
            $quantity = 1;
        } else {
            $quantity = (int) $quantity;
        }

        $size = $input->getArgument('size');
        if ($size === null) {
            $size = 1;
        } elseif (is_array($size)) {
            $size = 1;
        } else {
            $size = (int) $size;
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
            $keyset = $keyset->with(JWKFactory::createOctKey($size, $args));
        }
        $this->prepareJsonOutput($input, $output, $keyset);

        return 0;
    }
}
