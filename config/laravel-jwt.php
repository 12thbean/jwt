<?php

return [
    'algorithm' => env('LARAVEL_JWT_ALGORITHM', 'HS256'),

    'keys' => [
        'encode' => env('LARAVEL_JWT_ENCODE_KEY', env('APP_KEY')),
        'decode' => env('LARAVEL_JWT_DECODE_KEY', env('APP_KEY'))
    ],

    'payload' => [
        'iss' => env('APP_URL'),
    ],

    'token-ttl' => [
        'long-term' => env('LARAVEL_JWT_LONG_TERM_TOKEN_TTL', 60 * 60 * 24 * 365),
        'short-term' => env('LARAVEL_JWT_SHORT_TERM_TOKEN_TTL', 60 * 60 * 24)
    ],

    'blacklist-driver' => \Zendrop\LaravelJwt\BlacklistDrivers\DatabaseBlacklistDriver::class,

    'blacklist-database-table' => 'blacklist_tokens',

    'token-cookie-name' => env('JWT_TOKEN_KEY', 'token'), //cookie name
];
