<?php

namespace Zendrop\LaravelJwt\Exceptions;

class NonAuthenticatableModelException extends LaravelJwtException
{
    public function __construct(
        string $message = 'The model must implement the Authenticatable interface to use JWT.',
        int $code = 0,
        \Throwable $previous = null
    ) {
        if ($message) {
            parent::__construct($message, $code, $previous);
        }
    }
}
