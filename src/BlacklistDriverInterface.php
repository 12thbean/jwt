<?php

namespace Zendrop\LaravelJwt;

interface BlacklistDriverInterface
{
    public function add(Jwt|string $jwt): void;

    public function has(Jwt|string $jwt): bool;
}
