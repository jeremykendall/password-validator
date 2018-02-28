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
use JeremyKendall\Password\PasswordValidatorInterface;
use JeremyKendall\Password\Result as ValidationResult;
use JeremyKendall\Password\Storage\IdentityMissingException;
use JeremyKendall\Password\Storage\StorageInterface;
use PHPUnit\Framework\TestCase;

class StorageDecoratorTest extends TestCase
{

    /**
     * @var StorageDecorator
     */
    protected $decorator;

    /**
     * @var PasswordValidatorInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $decoratedValidator;

    /**
     * @var StorageInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $storage;

    protected function setUp()
    {
        $this->storage = $this->createMock(StorageInterface::class);
        $this->decoratedValidator = $this->createMock(PasswordValidatorInterface::class);
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
        $this->expectException(IdentityMissingException::class);
        $this->expectExceptionMessage('The StorageDecorator requires an $identity argument.');

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

        $this->decorator->isValid('password', 'passwordHash');
    }
}
