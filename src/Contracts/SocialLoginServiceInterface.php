<?php

namespace Redoy\AuthMaster\Contracts;

use Illuminate\Http\Request;

interface SocialLoginServiceInterface
{
    /**
     * Get the redirect URL for a social provider.
     *
     * @param string $provider The social provider name (e.g., 'google', 'facebook')
     * @return \Illuminate\Http\RedirectResponse
     * @throws \Redoy\AuthMaster\Exceptions\AuthException
     */
    public function redirect(string $provider): \Illuminate\Http\RedirectResponse;

    /**
     * Handle the callback from a social provider.
     *
     * @param string $provider The social provider name
     * @param Request $request The HTTP request
     * @return array Result with user data and token
     * @throws \Redoy\AuthMaster\Exceptions\AuthException
     */
    public function handleCallback(string $provider, Request $request): array;
}
