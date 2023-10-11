<?php

namespace Zendrop\LaravelJwt;

use Illuminate\Support\Carbon;

class DatabaseBlacklist implements BlacklistInterface
{
    public function add(Jwt $jwt): void
    {
        $hash = md5($jwt->encodedToken);

        if (BlacklistTokenModel::findByHash($hash)) {
            return;
        }

        $model = new BlacklistTokenModel();
        $model->hash = $hash;
        $model->expired_at = Carbon::createFromTimestamp($jwt->payload->exp);
        $model->save();
    }

    public function has(string|Jwt $jwt): bool
    {
        $hash = md5((string)$jwt);
        return (bool)BlacklistTokenModel::findByHash($hash);
    }

    public function removeExpired(): void
    {
        BlacklistTokenModel::query()
            ->where('expired_at', '<', now())
            ->delete();
    }
}