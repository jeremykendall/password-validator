<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Storage;

/**
 * Thrown when $identity argument is missing from
 * PasswordValidatorInterface::isValid() when StorageDecorator is in use
 */
class IdentityMissingException extends \InvalidArgumentException {}
