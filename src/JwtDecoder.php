<?php

namespace Zendrop\LaravelJwt;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Throwable;

class JwtDecoder implements JwtDecoderInterface
{
    public function __construct(
        protected Key $key
    ) {
    }

    public function decode(string $token): ?\Zendrop\LaravelJwt\Jwt
    {
        try {
            $decoded = JWT::decode($token, $this->key);
        } catch (Throwable $exception) {
            return null;
        }

        return new \Zendrop\LaravelJwt\Jwt(
            payload: new Payload(...(array)$decoded),
            encodedToken: $token
        );
    }
}