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
 * Abstract Decorator class
 */
abstract class AbstractDecorator implements PasswordValidatorInterface
{
    /**
     * @var PasswordValidatorInterface
     */
    protected $validator;

    /**
     * Public constructor
     *
     * @param PasswordValidatorInterface $validator Validator to be decorated
     */
    public function __construct(PasswordValidatorInterface $validator)
    {
        $this->validator = $validator;
    }

    /**
     * {@inheritDoc}
     */
    public function isValid($password, $passwordHash, $legacySalt = null, $identity = null)
    {
        return $this->validator->isValid($password, $passwordHash, $legacySalt, $identity);
    }

    /**
     * {@inheritDoc}
     */
    public function rehash($password)
    {
        return $this->validator->rehash($password);
    }

    /**
     * {@inheritDoc}
     */
    public function getOptions()
    {
        return $this->validator->getOptions();
    }

    /**
     * {@inheritDoc}
     */
    public function setOptions(array $options)
    {
        $this->validator->setOptions($options);
    }
}
