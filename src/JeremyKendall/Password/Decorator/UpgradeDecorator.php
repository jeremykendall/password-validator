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
    public function isValid($password, $passwordHash, $legacySalt = null, $identity = null)
    {
        $isValid = call_user_func(
            $this->validationCallback,
            $password,
            $passwordHash,
            $legacySalt
        );

        if ($isValid === true) {
            $passwordHash = password_hash($password, PASSWORD_DEFAULT, array(
                'cost' => 4,
                'salt' => 'CostAndSaltForceRehash',
            ));
        }

        return $this->validator->isValid($password, $passwordHash, $legacySalt, $identity);
    }
}
