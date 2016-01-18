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

    /**
     * The UpgradeDecorator hashes valid legacy passwords with a cost of 4 in 
     * order to force a rehash. Without the salt option to password_hash, 
     * removed for PHP 7.0 compatibility, the password will NOT be rehashed if 
     * the user provides a cost of 4 to 
     * PasswordValidatorInterface::setOptions().
     *
     * Adding this test before refactoring to avoid regressions.
     */
    public function testLegacyPasswordIsUpgradedEvenWhenUserProvidedCostIsFour()
    {
        $validator = new UpgradeDecorator(new PasswordValidator(), $this->callback);
        $validator->setOptions(array('cost' => 4));
        $password = 'password';
        $hash = hash('sha512', $password);

        $result = $validator->isValid($password, $hash);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $result->getCode(),
            'Failed asserting that Result::getCode() returns expected Result::SUCCESS_PASSWORD_REHASHED.'
        );
        $this->assertStringStartsWith('$2y$04', $result->getPassword());
    }
}
