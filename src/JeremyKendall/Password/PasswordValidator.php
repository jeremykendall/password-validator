<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password;

use JeremyKendall\Password\PasswordHashFailureException;
use JeremyKendall\Password\Result as ValidationResult;

/**
 * Validates user's password against password_hash function
 */
class PasswordValidator implements PasswordValidatorInterface
{
    /**
     * @var array password_hash options
     */
    protected $options = array();

    /**
     * {@inheritDoc}
     */
    public function isValid($password, $passwordHash)
    {
        $code = ValidationResult::FAILURE_PASSWORD_INVALID;
        $newHash = null;

        $isValid = password_verify($password, $passwordHash);
        $needsRehash = password_needs_rehash($passwordHash, PASSWORD_DEFAULT);

        if ($isValid === true) {
            $code = ValidationResult::SUCCESS;
        }

        if ($isValid === true && $needsRehash === true) {
            $newHash = $this->rehash($password);
            $code = ValidationResult::SUCCESS_PASSWORD_REHASHED;
        }

        return new ValidationResult($code, $newHash);
    }

    /**
     * {@inheritDoc}
     */
    public function rehash($password)
    {
        $hash = password_hash(
            $password,
            PASSWORD_DEFAULT,
            $this->getOptions()
        );

        // Ignoring b/c I have no idea how to make password_hash return false
        // @codeCoverageIgnoreStart
        if ($hash === false) {
            throw new PasswordHashFailureException('password_hash returned false.');
        }
        // @codeCoverageIgnoreEnd
        return $hash;
    }

    /**
     * {@inheritDoc}
     */
    public function getOptions()
    {
        return $this->options;
    }

    /**
     * {@inheritDoc}
     */
    public function setOptions(array $options)
    {
        $this->options = $options;
    }
}
