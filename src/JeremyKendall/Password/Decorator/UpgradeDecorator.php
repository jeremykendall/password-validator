<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Decorator;

use JeremyKendall\Password\PasswordValidatorInterface;
use JeremyKendall\Password\Result as ValidationResult;

/**
 * Validates user's password using a callback and upgrades password hash using
 * PHP's password_hash function
 */
class UpgradeDecorator extends AbstractDecorator
{
    /**
     * @var callback Legacy password validation via callback
     */
    protected $validationCallback;

    /**
     * Public constructor
     *
     * @param PasswordValidatorInterface $validator          Password validator
     * @param callable                   $validationCallback Callback used to validate legacy password hash
     */
    public function __construct(PasswordValidatorInterface $validator, $validationCallback)
    {
        parent::__construct($validator);
        $this->validationCallback = $validationCallback;
    }

    /**
     * {@inheritDoc}
     */
    public function isValid($password, $passwordHash)
    {
        $isValid = call_user_func(
            $this->validationCallback,
            $password,
            $passwordHash
        );

        if ($isValid === false) {
            return parent::isValid($password, $passwordHash);
        }

        $hash = $this->rehash($password);

        return new ValidationResult(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $hash
        );
    }
}
