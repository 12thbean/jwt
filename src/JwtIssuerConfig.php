<?php

namespace Zendrop\LaravelJwt;

class JwtIssuerConfig
{
    public function __construct(
        public readonly string $iss,
        public readonly ?int $ttl,
    ) {
    }
}
