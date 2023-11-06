<?php

namespace Zendrop\LaravelJwt;

interface JwtDecoderInterface
{
    public function decode(string $encodedToken): ?Jwt;
}
