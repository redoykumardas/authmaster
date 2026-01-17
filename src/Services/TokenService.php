<?php

namespace Redoy\AuthMaster\Services;

use Carbon\Carbon;
use Illuminate\Support\Str;
use Redoy\AuthMaster\Contracts\TokenServiceInterface;

class TokenService implements TokenServiceInterface
{
    public function createTokenForUser($user, string $deviceId = null): array
    {
        $driver = config('authmaster.driver', 'sanctum');
        $expirationMinutes = config('authmaster.tokens.expiration', 60 * 24);

        $tokenString = null;
        $expiresAt = Carbon::now()->addMinutes($expirationMinutes);

        // If user model supports createToken (Sanctum or Passport personal access tokens)
        if (method_exists($user, 'createToken')) {
            $token = $user->createToken($deviceId ?? 'authmaster-token');
            // $token->accessToken for passport; for sanctum $token->plainTextToken
            if (isset($token->plainTextToken)) {
                $tokenString = $token->plainTextToken;
            } elseif (isset($token->accessToken)) {
                $tokenString = $token->accessToken;
            }
            // try to persist token id if possible
            $tokenId = $token->accessToken->id ?? ($token->accessToken->id ?? null);
        } else {
            // fallback: generate random token; token persistence should be handled by DeviceSession
            $tokenString = Str::random(60);
            $tokenId = null;
        }

        return [
            'access_token' => $tokenString,
            'token_type' => 'Bearer',
            'expires_at' => $expiresAt->toDateTimeString(),
            'token_id' => $tokenId,
        ];
    }
}
