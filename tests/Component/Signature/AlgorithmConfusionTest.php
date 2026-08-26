<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class AlgorithmConfusionTest extends TestCase
{
    #[Test]
    public function legitimateProtectedAlgStillVerifies(): void
    {
        $key = $this->key();
        $algorithmManager = new AlgorithmManager([new HS256(), new HS512()]);
        $jws = (new JWSBuilder($algorithmManager))
            ->create()
            ->withPayload('payload')
            ->addSignature($key, [
                'alg' => 'HS256',
            ])
            ->build();

        $verifier = new JWSVerifier($algorithmManager);
        static::assertTrue($verifier->verifyWithKey($jws, $key, 0));
    }

    #[Test]
    public function unprotectedAlgDoesNotOverrideProtected(): void
    {
        $key = $this->key();
        $algorithmManager = new AlgorithmManager([new HS256(), new HS512()]);

        $jws = (new JWSBuilder($algorithmManager))
            ->create()
            ->withPayload('payload')
            ->addSignature($key, [
                'alg' => 'HS256',
            ])
            ->build();
        $serializer = new JSONFlattenedSerializer();
        $data = json_decode($serializer->serialize($jws, 0), true);
        $data['header'] = [
            'alg' => 'HS512',
        ];
        $tamperedJws = $serializer->unserialize(json_encode($data));

        $verifier = new JWSVerifier($algorithmManager);

        static::assertTrue($verifier->verifyWithKey($tamperedJws, $key, 0));
    }

    #[Test]
    public function algOnlyInUnprotectedHeaderIsRejected(): void
    {
        $key = $this->key();
        $algorithmManager = new AlgorithmManager([new HS256(), new HS512()]);

        $jws = (new JWSBuilder($algorithmManager))
            ->create()
            ->withPayload('payload')
            ->addSignature($key, [
                'alg' => 'HS256',
            ])
            ->build();
        $serializer = new JSONFlattenedSerializer();
        $data = json_decode($serializer->serialize($jws, 0), true);
        unset($data['protected']);
        $data['header'] = [
            'alg' => 'HS256',
        ];
        $tamperedJws = $serializer->unserialize(json_encode($data));

        $verifier = new JWSVerifier($algorithmManager);
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('No "alg" parameter set in the protected header.');
        $verifier->verifyWithKey($tamperedJws, $key, 0);
    }

    private function key(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'dKaQUMb3qDMRdfg6qLqsGgG-aWdh6cd1F6tXrXddzpc',
        ]);
    }
}
