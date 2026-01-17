<?php

namespace Redoy\AuthMaster\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Redoy\AuthMaster\Services\EmailVerificationService;
use Redoy\CoreModule\Facades\CoreResponse;
use Redoy\CoreModule\Constants\ApiCodes;

class EnsureEmailIsVerified
{
    protected EmailVerificationService $emailVerification;

    public function __construct(EmailVerificationService $emailVerification)
    {
        $this->emailVerification = $emailVerification;
    }

    /**
     * Handle an incoming request.
     * Block access if email verification is required but not completed.
     */
    public function handle(Request $request, Closure $next)
    {
        // Skip if email verification is not enabled
        if (!$this->emailVerification->isVerificationRequired()) {
            return $next($request);
        }

        $user = $request->user();

        // No user = not authenticated, let auth middleware handle it
        if (!$user) {
            return $next($request);
        }

        // Check if email is verified
        if (!$this->emailVerification->isVerified($user)) {
             return CoreResponse::errorResponse(
                 [
                    'email_verification_required' => true,
                    'email_verification_method' => $this->emailVerification->getVerificationMethod(),
                 ],
                 ApiCodes::FORBIDDEN,
                 'Your email address is not verified.'
             );
        }

        return $next($request);
    }
}
