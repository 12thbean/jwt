<?php

return [
    'algorithm' => env('LARAVEL_JWT_ALGORITHM', 'HS256'),

    'keys' => [
        'encode' => env('LARAVEL_JWT_ENCODE_KEY', env('APP_KEY')),
        'decode' => env('LARAVEL_JWT_DECODE_KEY', env('APP_KEY'))
    ],

    'payload' => [
        'iss' => env('APP_URL'),
        'ttl' => env('LARAVEL_JWT_TTL'),
    ],

    'blacklist-driver' => \Zendrop\LaravelJwt\DatabaseBlacklist::class,

    'blacklist-database-table' => 'blacklist_tokens'
];