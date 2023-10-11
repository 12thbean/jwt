<?php

namespace Zendrop\LaravelJwt;

use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\Authenticatable;

class JwtIssuer implements JwtIssuerInterface
{
    public function __construct(
        protected string $key,
        protected string $algorythm,
        protected JwtIssuerConfig $config,
    ) {
    }

    public function makeJwt(Authenticatable $authenticatable): \Zendrop\LaravelJwt\Jwt
    {
        $payload = new Payload(
            iss: $this->config->iss,
            iat: time(),
            uid: $authenticatable->getAuthIdentifier(),
            exp: $this->config->ttl ? time() + $this->config->ttl : null,
            pwh: $authenticatable->getAuthPassword(),
        );

        $encodedToken = JWT::encode(
            payload: $payload->toArray(),
            key: $this->key,
            alg: $this->algorythm
        );

        return new \Zendrop\LaravelJwt\Jwt(
            payload: $payload,
            encodedToken: $encodedToken
        );
    }
}
