<?php

namespace Zendrop\LaravelJwt;

class Jwt
{
    public function __construct(
        public readonly Payload $payload,
        public readonly string $encodedToken
    ) {
    }

    public function __toString(): string
    {
        return $this->encodedToken;
    }
}