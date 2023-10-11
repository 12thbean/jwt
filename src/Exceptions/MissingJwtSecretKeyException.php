<?php

namespace Zendrop\LaravelJwt\Exceptions;

class MissingJwtSecretKeyException extends LaravelJwtException
{
    protected $message = 'The JWT secret key is missing in the configuration.';
}
