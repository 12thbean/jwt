# Laravel JWT Guard

This package provides a simple way to use JWT (JSON Web Tokens) as an authentication guard in a Laravel
application.

## Requirements

| Package             | Supported versions |
|---------------------|--------------------|
| PHP                 | 8.2+ (8.3+ on Laravel 13) |
| `laravel/framework` | 12, 13             |
| `firebase/php-jwt`  | 6.8+, 7            |

> **`firebase/php-jwt` 7 enforces a minimum signing key size.** With HMAC algorithms
> (`HS256`/`HS384`/`HS512`) a key shorter than 32 bytes makes token issuing fail with
> `DomainException: Provided key is too short`. Laravel's `APP_KEY` is long enough; a custom
> `LARAVEL_JWT_ENCODE_KEY` may not be. Check your keys before upgrading `firebase/php-jwt`
> from 6 to 7, or pin `firebase/php-jwt` to `^6.8` until the keys are rotated.

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

## Signing key rotation

The decode key accepts a comma-separated list, so the signing key can be rotated without
invalidating tokens that are already in the wild:

```dotenv
LARAVEL_JWT_ENCODE_KEY="base64:NEW_KEY"
LARAVEL_JWT_DECODE_KEY="base64:NEW_KEY,base64:OLD_KEY"
```

New tokens are signed with the encode key. On verification the keys are tried in order, so
the first decode key must match the encode key; the rest are fallbacks for previously issued
tokens. Once the old tokens have drained, remove the old key from the list.

Whenever a token is verified by a fallback key (any key other than the first one), the package
dispatches a `Zendrop\LaravelJwt\Events\JwtDecodedUsingFallbackKey` event carrying the decoded
`Jwt` and the matched key index. Listen to it to track how much traffic still relies on the
old key before withdrawing it.

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
