<?php

namespace Redoy\AuthMaster\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Redoy\AuthMaster\Contracts\AuthManagerInterface;
use Redoy\AuthMaster\Contracts\RegistrationServiceInterface;
use Redoy\AuthMaster\DTOs\LoginData;
use Redoy\AuthMaster\DTOs\PasswordResetData;
use Redoy\AuthMaster\DTOs\RegisterData;
use Redoy\AuthMaster\DTOs\VerifyEmailData;
use Redoy\AuthMaster\Exceptions\AuthException;
use Redoy\AuthMaster\Exceptions\InvalidCredentialsException;
use Redoy\AuthMaster\Exceptions\TooManyAttemptsException;
use Redoy\AuthMaster\Exceptions\TwoFactorRequiredException;
use Redoy\AuthMaster\Http\Requests\ChangePasswordRequest;
use Redoy\AuthMaster\Http\Requests\ForgotPasswordRequest;
use Redoy\AuthMaster\Http\Requests\LoginRequest;
use Redoy\AuthMaster\Http\Requests\RegisterRequest;
use Redoy\AuthMaster\Http\Requests\ResetPasswordRequest;
use Redoy\AuthMaster\Http\Requests\UpdateProfileRequest;
use Redoy\AuthMaster\Http\Requests\Verify2faRequest;
use Redoy\AuthMaster\Http\Requests\VerifyEmailRequest;
use Redoy\AuthMaster\Traits\ApiResponse;

class AuthController extends Controller
{
    use ApiResponse;

    public function __construct(
        protected AuthManagerInterface $authManager,
        protected RegistrationServiceInterface $registrationService
    ) {
    }

    public function login(LoginRequest $request): JsonResponse
    {
        $data = LoginData::fromRequest($request);
        $result = $this->authManager->loginWithData($data);

        return $this->success($result, 'Logged in');
    }

    public function register(RegisterRequest $request): JsonResponse
    {
        $data = RegisterData::fromRequest($request);
        $result = $this->registrationService->register($data);

        $statusCode = $result->pendingRegistration ? 200 : 201;

        return $this->success($result->toArray(), $result->message ?? 'Registered', $statusCode);
    }

    public function verifyEmail(VerifyEmailRequest $request): JsonResponse
    {
        $data = VerifyEmailData::fromRequest($request);
        $result = $this->registrationService->verifyEmail($data);

        $statusCode = $result->token ? 201 : 200;

        return $this->success($result->toArray(), $result->message ?? 'Email verified', $statusCode);
    }

    public function resendVerification(Request $request): JsonResponse
    {
        $user = $request->user();

        if (!$user) {
            throw new AuthException('Authentication required', 401);
        }

        $this->registrationService->resendVerification($user);

        return $this->success([], 'Verification sent');
    }

    public function logout(Request $request): JsonResponse
    {
        $this->authManager->logoutCurrentDevice($request);

        return $this->success([], 'Logged out');
    }

    public function logoutAll(Request $request): JsonResponse
    {
        $this->authManager->logoutAllDevices($request);

        return $this->success([], 'Logged out from all devices');
    }

    public function profile(Request $request): JsonResponse
    {
        return $this->success(['user' => $request->user()]);
    }

    public function updateProfile(UpdateProfileRequest $request): JsonResponse
    {
        $user = $this->authManager->updateProfile($request->user(), $request->validated());

        return $this->success(['user' => $user], 'Profile updated');
    }

    public function changePassword(ChangePasswordRequest $request): JsonResponse
    {
        $result = $this->authManager->changePassword($request->user(), $request->validated());

        if (!$result['success']) {
            throw new AuthException($result['message'] ?? 'Failed to change password', 422);
        }

        return $this->success([], 'Password changed');
    }

    public function forgotPassword(ForgotPasswordRequest $request): JsonResponse
    {
        $result = $this->authManager->sendPasswordResetLink($request->validated());

        if (!$result['success']) {
            throw new AuthException($result['message'] ?? 'Failed to send reset email', 422);
        }

        return $this->success([], 'Reset email sent');
    }

    public function resetPassword(ResetPasswordRequest $request): JsonResponse
    {
        $data = PasswordResetData::fromRequest($request);
        $result = $this->authManager->resetPasswordWithData($data);

        if (!$result['success']) {
            throw new AuthException($result['message'] ?? 'Failed to reset password', 422);
        }

        return $this->success([], 'Password reset');
    }

    public function send2fa(Request $request): JsonResponse
    {
        $user = $request->user();

        if (!$user) {
            throw new AuthException('Authentication required', 401);
        }

        $result = $this->authManager->sendTwoFactor($user);

        if (!$result['success']) {
            throw new AuthException($result['message'] ?? 'Failed to send OTP', 422);
        }

        return $this->success([], 'OTP sent');
    }

    public function verify2fa(Verify2faRequest $request): JsonResponse
    {
        $result = $this->authManager->verifyTwoFactor($request->user(), $request->validated('code'));

        if (!$result['success']) {
            throw new AuthException($result['message'] ?? 'Invalid code', 422);
        }

        return $this->success([], 'OTP verified');
    }

    public function socialRedirect(Request $request, string $provider)
    {
        $result = $this->authManager->socialRedirect($provider);

        if (isset($result['redirect'])) {
            return $result['redirect'];
        }

        throw new AuthException($result['message'] ?? 'Provider not available', 400);
    }

    public function socialCallback(Request $request, string $provider): JsonResponse
    {
        $result = $this->authManager->handleSocialCallback($provider, $request);

        if (!$result['success']) {
            throw new AuthException($result['message'] ?? 'Social login failed', 400);
        }

        return $this->success($result['data'], 'Social login successful');
    }
}
