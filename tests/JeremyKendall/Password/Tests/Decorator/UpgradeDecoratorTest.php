<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Tests\Decorator;

use JeremyKendall\Password\Decorator\UpgradeDecorator;
use JeremyKendall\Password\Result as ValidationResult;

class UpgradeDecoratorTest extends \PHPUnit_Framework_TestCase
{
    private $decorator;

    private $decoratedValidator;

    private $validationCallback;

    protected function setUp()
    {
        parent::setUp();
        $this->validationCallback = function ($credential, $passwordHash) {
            if (hash('sha512', $credential) === $passwordHash) {
                return true;
            }

            return false;
        };
 
        $this->decoratedValidator = $this->getMockBuilder('JeremyKendall\Password\PasswordValidatorInterface')
            ->disableOriginalConstructor()
            ->getMock();

        $this->decorator = new UpgradeDecorator(
            $this->decoratedValidator,
            $this->validationCallback
        );
    }

    public function testPasswordValidAndPasswordRehashed()
    {
        $password = 'password';
        $passwordHash = hash('sha512', $password);

        $validatorRehash = password_hash($password, PASSWORD_DEFAULT);

        $result = new ValidationResult(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $validatorRehash
        );

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with($password, $this->isType('string'))
            ->will($this->returnValue($result));

        $result = $this->decorator->isValid($password, $passwordHash);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS_PASSWORD_REHASHED, 
            $result->getCode()
        );
        // Rehashed password is a valid hash
        $this->assertTrue(password_verify($password, $result->getPassword()));
    }

    public function testLegacyPasswordInvalidDecoratedValidatorTakesOver()
    {
        $passwordHash = hash('sha512', 'passwordz');

        $this->decoratedValidator->expects($this->never())
            ->method('rehash');

        $invalid = new ValidationResult(
            ValidationResult::FAILURE_PASSWORD_INVALID
        );

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with('password', $passwordHash)
            ->will($this->returnValue($invalid));

        $result = $this->decorator->isValid('password', $passwordHash);

        $this->assertFalse($result->isValid());
        $this->assertEquals(
            ValidationResult::FAILURE_PASSWORD_INVALID,
            $result->getCode()
        );
    }

    public function testPasswordHashPasswordValidDecoratedValidatorTakesOver()
    {
        $passwordHash = password_hash('password', PASSWORD_DEFAULT);

        $this->decoratedValidator->expects($this->never())
            ->method('rehash');

        $valid = new ValidationResult(
            ValidationResult::SUCCESS
        );

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with('password', $passwordHash)
            ->will($this->returnValue($valid));

        $result = $this->decorator->isValid('password', $passwordHash);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS, 
            $result->getCode()
        );
        $this->assertNull($result->getPassword());
    }

    public function testGetSetOptions()
    {
        $this->decoratedValidator->expects($this->at(0))
            ->method('getOptions')
            ->will($this->returnValue(array()));

        $this->decoratedValidator->expects($this->at(1))
            ->method('setOptions')
            ->with(array('cost' => '11'));

        $this->decoratedValidator->expects($this->at(2))
            ->method('getOptions')
            ->will($this->returnValue(array('cost' => '11')));

        $this->assertEquals(array(), $this->decorator->getOptions());
        $this->decorator->setOptions(array('cost' => '11'));
        $this->assertEquals(array('cost' => '11'), $this->decorator->getOptions());
    }
}
