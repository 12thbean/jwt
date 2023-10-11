<?php

namespace Zendrop\LaravelJwt;

use Illuminate\Contracts\Support\Arrayable;

class Payload implements Arrayable
{
    public function __construct(
        public readonly string $iss,
        public readonly int $iat,
        public readonly string|int $uid,
        public readonly ?int $exp,
        public readonly string $pwh
    ) {
    }

    public function toArray()
    {
        return [
            'iss' => $this->iss,
            'iat' => $this->iat,
            'uid' => $this->uid,
            'exp' => $this->exp,
            'pwh' => $this->pwh
        ];
    }
}