<?php

namespace Zendrop\LaravelJwt\BlacklistDrivers;

use Illuminate\Support\Carbon;
use Zendrop\LaravelJwt\BlacklistDriverInterface;
use Zendrop\LaravelJwt\Jwt;
use Zendrop\LaravelJwt\JwtDecoderInterface;
use Zendrop\LaravelJwt\Models\BlacklistTokenModel;

class DatabaseBlacklistDriver implements BlacklistDriverInterface
{
    public function __construct(
        protected readonly JwtDecoderInterface $jwtDecoder
    ) {
    }

    public function add(Jwt|string $jwt): void
    {
        if (is_string($jwt)) {
            $jwt = $this->jwtDecoder->decode($jwt);
            if ($jwt === null) {
                return;
            }
        }

        $hash = md5($jwt->encodedToken);

        if (BlacklistTokenModel::findByHash($hash)) {
            return;
        }

        $model = new BlacklistTokenModel();
        $model->hash = $hash;
        $model->expired_at = Carbon::createFromTimestamp($jwt->payload->exp);
        $model->save();
    }

    public function has(Jwt|string $jwt): bool
    {
        $hash = md5((string) $jwt);
        return (bool) BlacklistTokenModel::findByHash($hash);
    }

    public function removeExpired(): void
    {
        BlacklistTokenModel::query()
            ->where('expired_at', '<', now())
            ->delete();
    }
}
