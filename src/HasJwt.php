<?php

namespace Zendrop\LaravelJwt;

use Illuminate\Contracts\Auth\Authenticatable;
use Zendrop\LaravelJwt\Exceptions\NonAuthenticatableModelException;

trait HasJwt
{
    public function makeJwt(
        bool $shortTerm = false,
        bool $forceNew = false,
    ): Jwt {
        /** @var JwtIssuerInterface $jwtIssuer */
        $jwtIssuer = app(JwtIssuerInterface::class);

        if (!is_a($this, Authenticatable::class)) {
            throw new NonAuthenticatableModelException();
        }

        return $jwtIssuer->makeJwt($this, $shortTerm, $forceNew);
    }
}
