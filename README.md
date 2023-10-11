# Laravel JWT Guard

This package provides a simple way to use JWT (JSON Web Tokens) as an authentication guard in a Laravel
application.

## Installation

Require package `zendrop/laravel-jwt`

```bash
composer require zendrop/laravel-jwt
```

## Setup

After installation, you need to add service provider to your `config/app.php`

```php
'providers' => [
    ...
    Zendrop\LaravelJwt\LaravelJwtAuthServiceProvider::class,
]
```

and publish the package configuration with command

```bash
php artisan vendor:publish
```

Don't forget to run migrations

```bash
php artisan migrate
```

## Configuration

Modify the generated `config/laravel-jwt.php` in the config folder to suit your needs:

1. Algorithm: Set the JWT algorithm you wish to use (default is HS256).
2. Keys: Specify the encode and decode keys. By default, it uses the APP_KEY from your Laravel .env file.
3. Payload: Configure issuer (iss) and time-to-live (ttl) for the JWT.
4. Blacklist Driver: Specify the driver used for handling blacklisted tokens (default is a database driver).

## Usage

### HasJwt Trait

Include the `HasJwt` trait in your User model or any other authenticatable model:

```php
use Zendrop\LaravelJwt\HasJwt;

class User extends Authenticatable {
    use HasJwt;
    ...
}
```

This provides the `makeJwt()` method to generate JWT for the user.

### JWT Guard

In your `auth.php` config file, you can define the JWT guard:

```php
'guards' => [
    'web' => [
        'driver' => 'session',
        'provider' => 'users',
        ...
    ],
    'api' => [
        'driver' => 'laravel-jwt', // Use the JWT guard
        'provider' => 'users', 
    ],
    ...
]
```

For stateful JWT:

```php
'guards' => [
    'web' => [
        'driver' => 'laravel-jwt-cookie',
        'provider' => 'users', 
    ],
]

```