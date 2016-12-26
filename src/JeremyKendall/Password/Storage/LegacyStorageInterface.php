<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Storage;

/**
 * Interface for storing rehashed hashes
 */
interface LegacyStorageInterface
{
    /**
     * Updates user's password and salt in persistent storage
     *
     * @param string $identity Unique user identifier
     * @param string $password New password hash
     * @param string $salt the salt needed to regenerate the legacy hash in conjunction with the plain text password
     */
    public function updateLegacyPassword($identity, $password, $salt);
}
