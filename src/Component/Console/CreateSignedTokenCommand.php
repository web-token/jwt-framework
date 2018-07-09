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

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\Question;

final class CreateSignedTokenCommand extends Command
{
    private $jsonConverter;
    private $signatureAlgorithmManagerFactory;
    private $serializerManagerFactory;
    private $payload;

    private $serializationMode;
    private $signatures = [];
    /**
     * @var string[]
     */
    private $algorithms = [];

    public function __construct(JsonConverter $jsonConverter, AlgorithmManagerFactory $signatureAlgorithmManagerFactory, JWSSerializerManagerFactory $serializerManagerFactory, string $name = null)
    {
        parent::__construct($name);
        $this->serializerManagerFactory = $serializerManagerFactory;
        $this->signatureAlgorithmManagerFactory = $signatureAlgorithmManagerFactory;
        $this->jsonConverter = $jsonConverter;
    }

    protected function configure()
    {
        parent::configure();
        $this
            ->setName('jws:create')
            ->setDescription('Create a signed token.')
            ->setHelp('This command can create a signed token.');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $this->askForAlgorithmAliases($input, $output);
        $this->askForPayload($input, $output);
        while (true) {
            $key = $this->askForSignatureKey($input, $output);
            if (null === $key) {
                break;
            }
            $protectedHeader = [];
            $this->askForSignatureProtectedHeader($input, $output, $protectedHeader);
            $header = [];
            $this->askForSignatureHeader($input, $output, $header);
            $this->signatures[] = [
                'key' => $key,
                'protected_header' => $protectedHeader,
                'header' => $header,
            ];
        }

        $this->askForSerializationMode($input, $output);

        $this->build($input, $output);
    }

    private function build(InputInterface $input, OutputInterface $output): void
    {
        $builderFactory = new JWSBuilderFactory($this->jsonConverter, $this->signatureAlgorithmManagerFactory);
        $builder = $builderFactory->create($this->algorithms);
        $jws = $builder
            ->create()
            ->withPayload($this->payload);

        foreach ($this->signatures as $signature) {
            $jws = $jws->addSignature($signature['key'], $signature['protected_header'], $signature['header']);
        }
        $jws = $jws->build();

        $serializerManager = $this->serializerManagerFactory->create([$this->serializationMode]);
        $token = $serializerManager->serialize($this->serializationMode, $jws);

        $output->writeln($token);
    }

    private function askForAlgorithmAliases(InputInterface $input, OutputInterface $output): void
    {
        $helper = $this->getHelper('question');
        $question = new ChoiceQuestion(
            'Please select the algorithm aliase(s) you want to use',
            $this->signatureAlgorithmManagerFactory->aliases()
        );
        $question->setMultiselect(true);

        $this->algorithms = $helper->ask($input, $output, $question);
    }

    private function askForPayload(InputInterface $input, OutputInterface $output): void
    {
        $helper = $this->getHelper('question');
        $question = new Question('Please enter the payload of the token (JSON)');
        $question->setValidator(function ($answer) {
            if (!is_string($answer)) {
                throw new \RuntimeException('Invalid payload');
            }

            return $answer;
        });
        $question->setNormalizer(function ($value) {
            return $value ? trim($value) : '';
        });
        $this->payload = $helper->ask($input, $output, $question);
    }

    private function askForSerializationMode(InputInterface $input, OutputInterface $output): void
    {
        $helper = $this->getHelper('question');
        $question = new ChoiceQuestion(
            'Please select the serialization mode',
                $this->serializerManagerFactory->names()
            );
        $question->setValidator(function ($answer) {
            if (!is_string($answer)) {
                throw new \RuntimeException('Invalid payload');
            }

            return $answer;
        });
        $question->setErrorMessage('Invalid serialization mode.');
        $this->serializationMode = $helper->ask($input, $output, $question);
    }

    private function askForSignatureKey(InputInterface $input, OutputInterface $output): ?JWK
    {
        $helper = $this->getHelper('question');
        $question = new Question('Please enter the signature key (JWK). Empty value to continue');
        $question->setValidator(function ($answer) {
            if (empty($answer)) {
                return null;
            }
            if (!is_string($answer)) {
                throw new \RuntimeException('Invalid key');
            }
            try {
                return JWK::createFromJson($answer);
            } catch (\Exception $e) {
                throw new \RuntimeException('Invalid key');
            }
        });
        $question->setNormalizer(function ($value) {
            return $value ? trim($value) : '';
        });

        return $helper->ask($input, $output, $question);
    }

    private function askForSignatureProtectedHeader(InputInterface $input, OutputInterface $output, array &$header): void
    {
        while (true) {
            $helper = $this->getHelper('question');
            $question = new Question('Please enter the protected header member key. Empty value to continue');
            $key = $helper->ask($input, $output, $question);
            if (empty($key)) {
                break;
            }

            $question = new Question(sprintf('Please enter the protected header member value for "%s"', $key));
            $value = $helper->ask($input, $output, $question);

            $header[$key] = $value;
        }
    }

    private function askForSignatureHeader(InputInterface $input, OutputInterface $output, array &$header): void
    {
        while (true) {
            $helper = $this->getHelper('question');
            $question = new Question('Please enter the header member key. Empty value to continue');
            $key = $helper->ask($input, $output, $question);
            if (empty($key)) {
                break;
            }

            $question = new Question(sprintf('Please enter the header member value for "%s"', $key));
            $value = $helper->ask($input, $output, $question);

            $header[$key] = $value;
        }
    }
}
