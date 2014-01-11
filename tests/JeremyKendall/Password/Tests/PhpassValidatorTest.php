<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Tests;

use JeremyKendall\Password\PhpassValidator;
use JeremyKendall\Password\Result as ValidationResult;
use PasswordHash;

class PhpassValidatorTest extends \PHPUnit_Framework_TestCase
{
    protected $validator;

    protected $hasher;

    protected function setUp()
    {
        parent::setUp();
        $this->validator = new PhpassValidator();
        $this->hasher = new PasswordHash(8, false);
        $this->setValidatorPhpVersion('5.3.0');
    }

    public function testClassWarnsAgainstUseIfPhpVersionGTE537()
    {
        $this->setExpectedException(
            'PHPUnit_Framework_Error',
            "Your version of PHP supports password_hash. Please switch to "
            . "JeremyKendall\Password\PasswordValidator",
            E_USER_WARNING
        );

        $this->setValidatorPhpVersion('5.3.7');
        $this->validator->testForPasswordHash();
    }

    public function testIsNotPortableIfPhpVersionGTEThan53()
    {
        $this->setValidatorPhpVersion('5.3.0');
        $this->assertFalse($this->validator->isPortable());
    }

    public function testIsPortableIfPhpVersionLT53()
    {
        $this->setValidatorPhpVersion('5.2.9');
        $this->assertTrue($this->validator->isPortable());
    }

    public function testPasswordIsValid()
    {
        $passwordHash = $this->hasher->HashPassword('password');

        $result = $this->validator->isValid('password', $passwordHash);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS,
            $result->getCode()
        );
        $this->assertNull($result->getPassword());
    }

    public function testPasswordIsInvalid()
    {
        $passwordHash = $this->hasher->HashPassword('password');

        $result = $this->validator->isValid('passwordz', $passwordHash);

        $this->assertFalse($result->isValid());
        $this->assertEquals(
            ValidationResult::FAILURE_PASSWORD_INVALID,
            $result->getCode()
        );
        $this->assertNull($result->getPassword());
    }

    /**
     * @dataProvider infoProvider
     */
    public function testPasswordGetInfo($hash, $info)
    {
        $reflectionMethod =
            new \ReflectionMethod('JeremyKendall\Password\PhpassValidator', 'configureValidator');
        $reflectionMethod->setAccessible(true);
        $reflectionMethod->invoke($this->validator);

        $this->assertEquals($info, $this->validator->passwordGetInfo($hash));
    }

    public function infoProvider()
    {
        return array(
            array(
                'foo',
                array('algoName' => 'unknown', 'options' => array())
            ),
            array(
                '$2a$',
                array('algoName' => 'unknown', 'options' => array())
            ),
            array(
                '_J9..rasmBYk8r9AiWNc',
                array('algoName' => 'extdes', 'options' => array('cost' => '_J9..'))
            ),
            array(
                '$H$DPbgpBeDGfUQsZCeycJNNplQiHTwAG1',
                array('algoName' => 'portable', 'options' => array('cost' => '10'))
            ),
            array(
                '$P$BbKjSXyRzWrpMlzbPo0WZMoo6KdopD0',
                array('algoName' => 'portable', 'options' => array('cost' => 8))
            ),
            array(
                '$2a$07$usesomesillystringfore2uDLvp1Ii2e./U9C8sBjqp8I90dH6hi',
                array('algoName' => 'blowfish', 'options' => array('cost' => 7))
            ),
            array(
                '$2a$10$usesomesillystringfore2uDLvp1Ii2e./U9C8sBjqp8I90dH6hi',
                array('algoName' => 'blowfish', 'options' => array('cost' => 10))
            ),
        );
    }

    public function testRehashReturnsNull()
    {
        $this->markTestIncomplete();
    }

    public function testGetSetOptions()
    {
        $options = array(
            'cost' => 8,
            'portable' => false,
        );

        $this->assertEquals($options, $this->validator->getOptions());
        $this->validator->setOptions(array('cost' => '11'));
        $this->assertEquals(
            array('cost' => '11', 'portable' => false),
            $this->validator->getOptions()
        );

        $this->validator->setOptions(array('portable' => true));
        $this->assertEquals(
            array('cost' => '11', 'portable' => true),
            $this->validator->getOptions()
        );
    }

    private function setValidatorPhpVersion($version)
    {
        $reflectionClass =
            new \ReflectionClass('JeremyKendall\Password\PhpassValidator');
        $reflectionProperty = $reflectionClass->getProperty('phpVersion');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->validator, $version);

    }
}
