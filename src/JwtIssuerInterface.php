<?php

namespace Zendrop\LaravelJwt;

use Illuminate\Contracts\Auth\Authenticatable;

interface JwtIssuerInterface
{
    public function makeJwt(Authenticatable $authenticatable, bool $shortTerm = false): Jwt;

    public function getLastIssued(Authenticatable $authenticatable): ?Jwt;
}
