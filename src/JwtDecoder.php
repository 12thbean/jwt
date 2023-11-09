<?php

namespace Zendrop\LaravelJwt;

use Firebase\JWT\JWT as FirebaseLibraryJwt;
use Firebase\JWT\Key as FirebaseLibraryDecodeKey;

class JwtDecoder implements JwtDecoderInterface
{
    public function __construct(
        protected FirebaseLibraryDecodeKey $key
    ) {
    }

    public function decode(string $encodedToken): ?Jwt
    {
        try {
            $decoded = (array) FirebaseLibraryJwt::decode($encodedToken, $this->key);
            $payload = new Payload(...$decoded);
        } catch (\Throwable $exception) {
            return null;
        }

        return new Jwt(
            payload: $payload,
            encodedToken: $encodedToken
        );
    }
}
