<?php

namespace Redoy\AuthMaster\Services;

use Redoy\AuthMaster\Contracts\OtpGeneratorInterface;

class OtpGenerator implements OtpGeneratorInterface
{
    /**
     * Generate a numeric OTP code.
     *
     * Uses dev OTP in non-production environments for easier testing.
     *
     * @param int $length The length of the OTP code
     * @return string The generated OTP code
     */
    public function generate(int $length = 6): string
    {
        $devOtp = config('authmaster.otp.dev_otp');

        if ($devOtp && !app()->isProduction()) {
            return (string) $devOtp;
        }

        return $this->generateSecureCode($length);
    }

    /**
     * Generate a cryptographically secure numeric code.
     *
     * @param int $length The length of the code
     * @return string The generated code
     */
    protected function generateSecureCode(int $length): string
    {
        $code = '';

        for ($i = 0; $i < $length; $i++) {
            $code .= (string) random_int(0, 9);
        }

        return $code;
    }
}
