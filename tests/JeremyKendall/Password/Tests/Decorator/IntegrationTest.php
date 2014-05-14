<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Tests\Decorator;

use JeremyKendall\Password\PasswordValidator;
use JeremyKendall\Password\Decorator\UpgradeDecorator;
use JeremyKendall\Password\Decorator\StorageDecorator;
use JeremyKendall\Password\Result as ValidationResult;
use JeremyKendall\Password\Storage\StorageInterface;

/**
 * @group integration
 */
class IntegrationTest extends \PHPUnit_Framework_TestCase
{
    protected $storage;

    protected function setUp()
    {
        parent::setUp();

        $this->callback = function ($credential, $passwordHash) {
            if (hash('sha512', $credential) === $passwordHash) {
                return true;
            }

            return false;
        };
        $this->storage = $this->getMock('JeremyKendall\Password\Storage\StorageInterface');
    }

    public function testLegacyPasswordIsValidUpgradedRehashedStored()
    {
        $validator = new UpgradeDecorator(
            new StorageDecorator(
                new PasswordValidator(), 
                $this->storage
            ), 
            $this->callback
        );
        $password = 'password';
        $hash = hash('sha512', $password);
        $identity = 'username';

        $this->storage->expects($this->once())
            ->method('updatePassword')
            ->with($identity, $this->stringContains('$2y$10$'));

        $result = $validator->isValid($password, $hash, null, $identity);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $result->getCode()
        );
        $this->assertNotNull($result->getPassword());
        $this->assertStringStartsWith('$2y$10$', $result->getPassword());
    }

    public function testLegacyPasswordIsValidUpgradedRehashedStored2()
    {
        $validator = new StorageDecorator(
            new UpgradeDecorator(
                new PasswordValidator(), 
                $this->callback
            ), 
            $this->storage
        );
        $password = 'password';
        $hash = hash('sha512', $password);
        $identity = 'username';

        $this->storage->expects($this->once())
            ->method('updatePassword')
            ->with($identity, $this->stringContains('$2y$10$'));

        $result = $validator->isValid($password, $hash, null, $identity);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $result->getCode()
        );
        $this->assertStringStartsWith('$2y$10$', $result->getPassword());
    }
}
