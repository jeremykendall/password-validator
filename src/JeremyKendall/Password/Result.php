<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password;

/**
 * Password Validation Result
 *
 * Brazenly stolen from the Zend Framework then heavily modified.
 * @see https://github.com/zendframework/zf2/blob/master/library/Zend/Password/Result.php
 */
class Result
{
    /**
     * General Failure
     */
    const FAILURE = 0;

    /**
     * Failure due to invalid credential being supplied.
     */
    const FAILURE_PASSWORD_INVALID = -3;

    /**
     * Password success.
     */
    const SUCCESS = 1;

    /**
     * Password success, credential rehashed
     */
    const SUCCESS_PASSWORD_REHASHED = 2;

    /**
     * Password result code
     *
     * @var int
     */
    protected $code;

    /**
     * Rehashed password
     *
     * Only present if password was rehashed
     *
     * @var string
     */
    protected $password;

    /**
     * Sets the result code and rehashed password
     *
     * @param int   $code
     * @param mixed $password
     */
    public function __construct($code, $password = null)
    {
        $this->code = (int) $code;
        $this->password = $password;
    }

    /**
     * Returns whether the result represents a successful authentication attempt
     *
     * @return bool
     */
    public function isValid()
    {
        return ($this->code > 0) ? true : false;
    }

    /**
     * getCode() - Get the result code for this authentication attempt
     *
     * @return int
     */
    public function getCode()
    {
        return $this->code;
    }

    /**
     * Returns the rehashed password
     *
     * Only present if password was rehashed
     *
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
    }
}
