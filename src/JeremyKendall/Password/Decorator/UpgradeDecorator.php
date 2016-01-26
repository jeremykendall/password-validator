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

    const DEFAULT_REHASH_COST = 4;

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
            $passwordHash = $this->createHashWhichWillForceRehashInValidator($password);
        }

        return $this->validator->isValid($password, $passwordHash, $legacySalt, $identity);
    }
    
    /**
     * This method returns an upgraded password, one that is hashed by the
     * password_hash method in such a way that it forces the PasswordValidator
     * to rehash the password. This results in PasswordValidator::isValid()
     * returning a Result::$code of Result::SUCCESS_PASSWORD_REHASHED,
     * notifying the StorageDecorator or custom application code that the
     * returned password hash should be persisted.
     *
     * @param string $password Password to upgrade
     *
     * @return string Hashed password
     */
    private function createHashWhichWillForceRehashInValidator($password)
    {
        $cost = static::DEFAULT_REHASH_COST;
        $options = $this->getOptions();

        if (isset($options['cost']) && (int) $options['cost'] === $cost) {
            $cost++;
        }

        return password_hash($password, PASSWORD_DEFAULT, array('cost' => $cost));
    }
}
