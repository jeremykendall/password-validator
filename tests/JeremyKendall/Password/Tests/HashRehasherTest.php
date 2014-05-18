<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Tests;

use JeremyKendall\Password\PasswordValidator;
use JeremyKendall\Password\HashRehasher;
use JeremyKendall\Password\Storage\LegacyStorageInterface;

class HashRehasherTest extends \PHPUnit_Framework_TestCase
{
    const PASSWORD   = 'thePassword';
    const SALT       = 'theSalt';
    const IDENTITY   = 'theUsername';
    const LEGACYHASH = 'ChangeMe';

    public function setUp()
    {
        $this->storage = new LegacyStorageSpy;
        $this->rehasher = new HashRehasher( $this->storage );
    }

    public function testCanCallRehashHash()
    {
        $this->rehasher->rehashHash( self::IDENTITY, self::LEGACYHASH, self::SALT );
    }

    /**
     * @expectedException JeremyKendall\Password\Storage\IdentityMissingException
     */
    public function testHashRehasherThrowsExceptionWhenCalledWithoutIdentity()
    {
        $this->rehasher->rehashHash( '', self::LEGACYHASH, self::SALT );
    }

    /**
     * @expectedException JeremyKendall\Password\Storage\HashMissingException
     */
    public function testHashRehasherThrowsExceptionWhenCalledWithoutHash()
    {
        $this->rehasher->rehashHash( self::IDENTITY, '', self::SALT );
    }

    public function testHashRehasherUpdates()
    {
        $this->rehasher->rehashHash( self::IDENTITY, self::LEGACYHASH, self::SALT );
        $this->assertEquals(self::IDENTITY, $this->storage->identity);
        $this->assertEquals(self::SALT, $this->storage->salt);
        $this->assertNotNull($this->storage->password);
    }

    public function testRehashedPasswordValidates()
    {
        $legacyHash = $this->hashLegacy(self::PASSWORD, self::SALT);
        $this->rehasher->rehashHash(self::IDENTITY, $legacyHash, self::SALT);
        $this->assertTrue(password_verify($legacyHash, $this->storage->password));
    }

    protected function hashLegacy($password, $salt)
    {
        return md5( $password . $salt );
    }
}

class LegacyStorageSpy implements LegacyStorageInterface
{
    public $identity;
    public $password;
    public $salt;

    public function updateLegacyPassword($identity, $password, $salt)
    {
        $this->identity = $identity;
        $this->password = $password;
        $this->salt = $salt;
    }
}
