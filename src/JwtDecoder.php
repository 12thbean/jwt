<?php

namespace Zendrop\LaravelJwt;

use Firebase\JWT\JWT as FirebaseLibraryJwt;
use Firebase\JWT\Key as FirebaseLibraryDecodeKey;
use Zendrop\LaravelJwt\Events\JwtDecodedUsingFallbackKey;

class JwtDecoder implements JwtDecoderInterface
{
    /**
     * @param non-empty-list<FirebaseLibraryDecodeKey> $keys The first key is the primary one; the rest are
     *                                                       fallbacks that keep previously issued tokens valid
     *                                                       during signing key rotation.
     */
    public function __construct(
        protected readonly array $keys
    ) {
    }

    public function decode(string $encodedToken): ?Jwt
    {
        foreach ($this->keys as $index => $key) {
            try {
                $decoded = (array) FirebaseLibraryJwt::decode($encodedToken, $key);
                $payload = new Payload(...$decoded);
            } catch (\Throwable $exception) {
                continue;
            }

            $jwt = new Jwt(
                payload: $payload,
                encodedToken: $encodedToken
            );

            if ($index > 0) {
                event(new JwtDecodedUsingFallbackKey($jwt, $index));
            }

            return $jwt;
        }

        return null;
    }
}
