<?php

namespace Zendrop\LaravelJwt\Tests\Fixtures;

use Illuminate\Foundation\Auth\User;
use Zendrop\LaravelJwt\HasJwt;

class GuardTestUser extends User
{
    use HasJwt;

    /**
     * @var string
     */
    protected $table = 'users';

    /**
     * @var bool
     */
    public $timestamps = false;

    /**
     * @var array<int, string>
     */
    protected $fillable = ['email', 'password'];
}
