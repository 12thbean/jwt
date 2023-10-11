<?php

namespace Zendrop\LaravelJwt\Exceptions;

class NonAuthenticatableModelException extends LaravelJwtException
{
    protected $message = 'The model must implement the Authenticatable interface to use JWT.';
}
