<?php

namespace Zendrop\LaravelJwt\Guards;

use Illuminate\Contracts\Auth\Guard;

class JwtGuard extends BaseJwtGuard implements Guard
{
    protected function extractTokenFromRequest(): ?string
    {
        return $this->request->bearerToken();
    }
}
