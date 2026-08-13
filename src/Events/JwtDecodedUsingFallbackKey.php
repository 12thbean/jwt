<?php

namespace Zendrop\LaravelJwt\Events;

use Zendrop\LaravelJwt\Jwt;

class JwtDecodedUsingFallbackKey
{
    public function __construct(
        public readonly Jwt $jwt,
        public readonly int $keyIndex,
    ) {
    }
}
