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
 * Password validator interface
 */
interface PasswordValidatorInterface
{
    /**
     * Validates password and rehashes if necessary.
     *
     * @param  string          $password     Password provided by user during login
     * @param  string          $passwordHash User's current hashed password
     * @param  string          $legacySalt   OPTIONAL salt used in legacy password hashing
     * @param  string          $identity     OPTIONAL unique user identifier
     * @return Result
     */
    public function isValid($password, $passwordHash, $legacySalt = null, $identity = null);

    /**
     * Hashes password using password_hash. Uses PASSWORD_DEFAULT encryption.
     *
     * @param  string                                $password Plain text password
     * @return string                                Hashed password
     * @throws PasswordHashFailureException If password_hash returns false
     */
    public function rehash($password);

    /**
     * Set options for password_hash function
     *
     * @see http://php.net/password_hash
     * Please, don't create your own salt. Really, just don't. Review the
     * documentation first if you feel you just gotta create your own salt.
     *
     * @param array $options password_hash options
     */
    public function setOptions(array $options);

    /**
     * Gets options for password_hash function
     *
     * @return array password_hash options
     */
    public function getOptions();
}
