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
use JeremyKendall\Password\PasswordValidatorInterface;
use PHPUnit\Framework\TestCase;

class AbstractDecoratorTest extends TestCase
{

    /**
     * @var AbstractDecorator
     */
    private $decorator;

    /**
     * @var PasswordValidatorInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $decoratedValidator;

    protected function setUp()
    {
        $this->decoratedValidator = $this->createMock(PasswordValidatorInterface::class);

        $this->decorator =
            $this->getMockBuilder(AbstractDecorator::class)
            ->setConstructorArgs(array($this->decoratedValidator))
            ->getMockForAbstractClass();
    }

    public function testIsValidWithoutOptionalArgs()
    {
        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with('password', 'passwordHash', null, null);

        $this->decorator->isValid('password', 'passwordHash');
    }

    public function testIsValidWithOptionalArgs()
    {
        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with('password', 'passwordHash', 'legacySalt', 'identity');

        $this->decorator->isValid('password', 'passwordHash', 'legacySalt', 'identity');
    }

    public function testRehash()
    {
        $this->decoratedValidator->expects($this->once())
            ->method('rehash')
            ->with('password');

        $this->decorator->rehash('password');
    }
}
