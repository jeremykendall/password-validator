<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Tests\Decorator;

use JeremyKendall\Password\Decorator\StorageDecorator;
use JeremyKendall\Password\Result as ValidationResult;
use JeremyKendall\Password\Storage\StorageInterface;

class StorageDecoratorTest extends \PHPUnit_Framework_TestCase
{
    protected $decorator;

    protected $decoratedValidator;

    protected $storage;

    protected function setUp()
    {
        parent::setUp();

        $this->storage = $this->getMock('JeremyKendall\Password\Storage\StorageInterface');
        $this->decoratedValidator = $this->getMockBuilder('JeremyKendall\Password\PasswordValidatorInterface')
            ->disableOriginalConstructor()
            ->getMock();
        $this->decorator = new StorageDecorator(
            $this->decoratedValidator,
            $this->storage
        );
    }

    public function testPasswordValidPasswordRehashedAndStored()
    {
        $valid = new ValidationResult(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            'rehashedPassword'
        );

        $this->storage->expects($this->once())
            ->method('updatePassword')
            ->with('username', 'rehashedPassword');

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with('password', 'passwordHash', null, 'username')
            ->will($this->returnValue($valid));

        $result = $this->decorator->isValid('password', 'passwordHash', null, 'username');

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $result->getCode()
        );
    }

    public function testFailureToProvideIdentityThrowsException()
    {
        $this->setExpectedException(
            'JeremyKendall\Password\Storage\IdentityMissingException',
            'The StorageDecorator requires an $identity argument.'
        );

        $valid = new ValidationResult(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            'rehashedPassword'
        );

        $this->storage->expects($this->never())
            ->method('updatePassword');

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with('password', 'passwordHash')
            ->will($this->returnValue($valid));

        $result = $this->decorator->isValid('password', 'passwordHash');
    }
}
