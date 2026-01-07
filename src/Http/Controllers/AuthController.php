<?php

namespace Redoy\AuthMaster\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
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
        // dd(RegisterData::fromRequest($request));
        return $this->registrationService->register(
            RegisterData::fromRequest($request)
        );
    }

    public function verifyEmail(VerifyEmailRequest $request)
    {
        return $this->registrationService->verifyEmail(
            VerifyEmailData::fromRequest($request)
        );
    }

    public function resendVerification(Request $request)
    {
        return $this->registrationService->resendVerification($request->user());
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
        return $this->authManager->sendTwoFactor($request->user());
    }

    public function verify2fa(Verify2faRequest $request)
    {
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
}
