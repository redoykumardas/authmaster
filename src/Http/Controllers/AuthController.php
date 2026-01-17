<?php

namespace Redoy\AuthMaster\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Redoy\CoreModule\Facades\CoreResponse;
use Redoy\CoreModule\Constants\ApiCodes;
use Redoy\AuthMaster\Contracts\AuthManagerInterface;
use Redoy\AuthMaster\Contracts\RegistrationServiceInterface;
use Redoy\AuthMaster\DTOs\AuthResult;
use Redoy\AuthMaster\DTOs\LoginData;
use Redoy\AuthMaster\DTOs\PasswordResetData;
use Redoy\AuthMaster\DTOs\RegisterData;
use Redoy\AuthMaster\DTOs\VerifyEmailData;
use Redoy\AuthMaster\Http\Requests\ChangePasswordRequest;
use Redoy\AuthMaster\Http\Requests\ForgotPasswordRequest;
use Redoy\AuthMaster\Http\Requests\LoginRequest;
use Redoy\AuthMaster\Http\Requests\RegisterRequest;
use Redoy\AuthMaster\Http\Requests\ResetPasswordRequest;
use Redoy\AuthMaster\Http\Requests\UpdateProfileRequest;
use Redoy\AuthMaster\Http\Requests\Verify2faRequest;
use Redoy\AuthMaster\Http\Requests\VerifyEmailRequest;

class AuthController extends Controller
{
    public function __construct(
        protected AuthManagerInterface $authManager,
        protected RegistrationServiceInterface $registrationService
    ) {
    }

    public function login(LoginRequest $request)
    {
        return $this->authManager->loginWithData(
            LoginData::fromRequest($request)
        );
    }

    public function register(RegisterRequest $request)
    {
        return $this->registrationService->register();
    }

    public function verifyEmail(VerifyEmailRequest $request)
    {
        return $this->registrationService->verifyEmail(
            VerifyEmailData::fromRequest($request)
        );
    }


    public function logout(Request $request)
    {
        $this->authManager->logoutCurrentDevice($request);
        return new AuthResult(message: 'Logged out');
    }

    public function logoutAll(Request $request)
    {
        $this->authManager->logoutAllDevices($request);
        return new AuthResult(message: 'Logged out from all devices');
    }

    public function profile(Request $request)
    {
        return new AuthResult(user: $request->user());
    }

    public function updateProfile(UpdateProfileRequest $request)
    {
        return $this->authManager->updateProfile(
            $request->user(),
            $request->validated()
        );
    }

    public function changePassword(ChangePasswordRequest $request)
    {
        return $this->authManager->changePassword(
            $request->user(),
            $request->validated()
        );
    }

    public function forgotPassword(ForgotPasswordRequest $request)
    {
        return $this->authManager->sendPasswordResetLink($request->validated());
    }

    public function resetPassword(ResetPasswordRequest $request)
    {
        return $this->authManager->resetPasswordWithData(
            PasswordResetData::fromRequest($request)
        );
    }

    public function send2fa(Request $request)
    {
        // 1. If temp_token is present, we are resending for a pending login
        if ($request->filled('temp_token')) {
             $deviceId = $request->header('device_id')
            ?? $request->header('X-Device-Id')
            ?? $request->header('Device-Id')
            ?? hash('sha256', (string) $request->ip() . '|' . (string) $request->userAgent());

            return $this->authManager->resendTwoFactorLogin(
                $request->input('temp_token'),
                $deviceId
            );
        }

        // 2. Check if user is authenticated via Sanctum/Guard
        $user = $request->user();
        
        if ($user) {
             return $this->authManager->sendTwoFactor($user);
        }

        return CoreResponse::errorResponse([], ApiCodes::UNAUTHORIZED, 'Unauthenticated');
    }

    public function verify2fa(Verify2faRequest $request)
    {
        // 1. If temp_token is present, we are completing a login
        if ($request->filled('temp_token')) {
            $deviceId = $request->header('device_id')
            ?? $request->header('X-Device-Id')
            ?? $request->header('Device-Id')
            ?? hash('sha256', (string) $request->ip() . '|' . (string) $request->userAgent());
            
            return $this->authManager->verifyTwoFactorLogin(
                $request->validated('temp_token'),
                $request->validated('code'),
                $deviceId,
                $request->header('X-Device-Name') ?? $request->header('Device-Name'), // optional device name
                $request->ip(),
                $request->userAgent()
            );
        }

        // 2. Otherwise, we assume the user is already authenticated (e.g. verifying for sensitive action)
        return $this->authManager->verifyTwoFactor(
            $request->user(),
            $request->validated('code')
        );
    }

    public function socialRedirect(Request $request, string $provider)
    {
        $result = $this->authManager->socialRedirect($provider);

        // Handle special redirect logic if needed, 
        // though AuthResult::toResponse could also handle it if we add a redirect property.
        if ($result->user instanceof \Illuminate\Http\RedirectResponse) {
            return $result->user;
        }

        return $result;
    }

    public function socialCallback(Request $request, string $provider)
    {
        return $this->authManager->handleSocialCallback($provider, $request);
    }

    public function devices(Request $request)
    {
        $devices = $this->authManager->getDevices($request->user());
        return new AuthResult(data: ['devices' => $devices], status: 200);
    }

    public function removeDevice(Request $request, string $deviceId)
    {
        $this->authManager->removeDevice($request->user(), $deviceId);
        return new AuthResult(message: 'Device removed successfully', status: 200);
    }
}
