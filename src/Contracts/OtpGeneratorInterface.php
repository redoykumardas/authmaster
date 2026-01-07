<?php

namespace Redoy\AuthMaster\Contracts;

interface OtpGeneratorInterface
{
    /**
     * Generate a numeric OTP code.
     *
     * @param int $length The length of the OTP code
     * @return string The generated OTP code
     */
    public function generate(int $length = 6): string;
}
