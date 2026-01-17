<?php

use Illuminate\Support\Facades\Route;
use Redoy\AuthMaster\Http\Controllers\AuthController;

Route::prefix('auth')->group(function () {
    // Public routes
    Route::post('login', [AuthController::class, 'login'])
        ->middleware('throttle:' . config('authmaster.security.max_login_attempts', 5) . ',1');

    Route::post('register', [AuthController::class, 'register'])
        ->middleware('throttle:' . config('authmaster.security.max_registration_attempts_per_device', 3) . ',1');

    Route::post('password/email', [AuthController::class, 'forgotPassword']);
    Route::post('password/reset', [AuthController::class, 'resetPassword']);

    Route::post('social/{provider}', [AuthController::class, 'socialRedirect']);
    Route::get('social/{provider}/callback', [AuthController::class, 'socialCallback']);

    // 2FA endpoints
    Route::post('2fa/verify', [AuthController::class, 'verify2fa']);
    Route::post('2fa/send', [AuthController::class, 'send2fa']);

    // Email verification
    Route::match(['get', 'post'], 'verify-email', [AuthController::class, 'verifyEmail']);

    // Protected routes
    $authMiddleware = config('authmaster.auth_middleware', 'auth:sanctum');

    Route::middleware([$authMiddleware])->group(function () {
        Route::post('logout', [AuthController::class, 'logout']);
        Route::post('logout/all', [AuthController::class, 'logoutAll']);
        Route::get('profile', [AuthController::class, 'profile']);
        Route::patch('profile', [AuthController::class, 'updateProfile']);
        Route::post('password/change', [AuthController::class, 'changePassword']);

        Route::get('devices', [AuthController::class, 'devices']);
        Route::delete('devices/{deviceId}', [AuthController::class, 'removeDevice']);
    });
});
