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
use JeremyKendall\Password\Storage\IdentityMissingException;
use JeremyKendall\Password\Storage\StorageInterface;

/**
 * Storage decorator persists new user hash if password rehashed
 */
class StorageDecorator extends AbstractDecorator
{
    /**
     * @var StorageInterface Instance of class implementing StorageInterface
     */
    protected $storage;

    /**
     * Public constructor
     *
     * @param PasswordValidatorInterface $validator Password validator
     * @param StorageInterface           $storage   Storage class
     */
    public function __construct(
        PasswordValidatorInterface $validator,
        StorageInterface $storage
    )
    {
        parent::__construct($validator);
        $this->storage = $storage;
    }

    /**
     * {@inheritDoc}
     * @throws IdentityMissingException If $identity isn't provided
     */
    public function isValid($password, $passwordHash, $legacySalt = null, $identity = null)
    {
        $result = $this->validator->isValid($password, $passwordHash, $legacySalt, $identity);
        $rehashed = ($result->getCode() === ValidationResult::SUCCESS_PASSWORD_REHASHED);

        if ($rehashed && $identity === null) {
            throw new IdentityMissingException(
                'The StorageDecorator requires an $identity argument.'
            );
        }

        if ($rehashed) {
            $this->storage->updatePassword($identity, $result->getPassword());
        }

        return $result;
    }
}
