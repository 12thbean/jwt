<?php

namespace Zendrop\LaravelJwt\Traits;

use Illuminate\Http\Request;

trait ExtractTokenFromRequestTrait
{
    protected function extractTokenFromRequest(Request $request): ?string
    {
        $token = $request->bearerToken() ?? $request->cookie('token');

        if (empty($token)) {
            return null;
        }

        return $token;
    }
}
