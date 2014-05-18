<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password;

use JeremyKendall\Password\Storage\IdentityMissingException;
use JeremyKendall\Password\Storage\HashMissingException;
use JeremyKendall\Password\Storage\LegacyStorageInterface;
/**
 * Rehashes a legacy password hash
 */
class HashRehasher
{
    protected $storage;

    public function __construct(LegacyStorageInterface $storage)
    {
        $this->storage = $storage;
    }

    public function rehashHash($identity, $hash, $salt = null)
    {
        if (!$identity) {
            throw new IdentityMissingException(
                'The HashRehasher requires an $identity.'
            );
        }

        if (!$hash) {
            throw new HashMissingException(
                'The HashRehasher requires a $hash.'
            );
        }

        $this->storage->updateLegacyPassword($identity, password_hash($hash, PASSWORD_DEFAULT), $salt);
    }

}
