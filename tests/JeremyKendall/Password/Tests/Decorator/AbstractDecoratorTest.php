<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Tests\Decorator;

use JeremyKendall\Password\Decorator\AbstractDecorator;

class AbstractDecoratorTest extends \PHPUnit_Framework_TestCase
{
    private $decorator;

    private $decoratedValidator;

    protected function setUp()
    {
        parent::setUp();

        $this->decoratedValidator = $this->getMockBuilder('JeremyKendall\Password\PasswordValidatorInterface')
            ->disableOriginalConstructor()
            ->getMock();

        $this->decorator = 
            $this->getMockBuilder('JeremyKendall\Password\Decorator\AbstractDecorator')
            ->setConstructorArgs(array($this->decoratedValidator))
            ->getMockForAbstractClass();
    }

    public function testIsValid()
    {
        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with('password', 'passwordHash', null);

        $this->decorator->isValid('password', 'passwordHash');
    }

    public function testRehash()
    {
        $this->decoratedValidator->expects($this->once())
            ->method('rehash')
            ->with('password');

        $this->decorator->rehash('password');
    }
}
