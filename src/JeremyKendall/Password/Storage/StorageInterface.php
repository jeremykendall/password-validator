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
 * Interface for storage classes
 */
interface StorageInterface
{
    /**
     * Updates user's password in persistent storage
     *
     * @param string $identity Unique user identifier
     * @param string $password New password hash
     */
    public function updatePassword($identity, $password);
}
