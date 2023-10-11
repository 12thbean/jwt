<?php

namespace Zendrop\LaravelJwt;

interface BlacklistInterface
{
    public function add(Jwt $jwt): void;

    public function has(Jwt|string $jwt): bool;
}