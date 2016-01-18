<?php

/**
 * Password Validator.
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 *
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Tests;

trait BlowfishCallbackConstraintTrait
{
    /**
     * Gets callback constraint to validate blowfish encrypted password.
     *
     * @param string $cost Cost used in pattern. Must be 0 padded if less than 10
     *
     * @return callable
     */
    public function getBlowfishCallback($cost = '10')
    {
        $pattern = sprintf('/^\$2y\$%s\$.{53}$/', $cost);

        return function ($subject) use ($pattern) {
            return preg_match($pattern, $subject) === 1;
        };
    }
}
