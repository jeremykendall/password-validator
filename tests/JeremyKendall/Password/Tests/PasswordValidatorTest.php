<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password\Tests;

use JeremyKendall\Password\PasswordValidator;
use JeremyKendall\Password\Result as ValidationResult;
use PHPUnit\Framework\TestCase;

class PasswordValidatorTest extends TestCase
{
    /**
     * @var PasswordValidator
     */
    private $validator;

    protected function setUp()
    {
        $this->validator = new PasswordValidator();
    }

    public function testPasswordIsValidDoesNotNeedRehash()
    {
        $passwordHash = password_hash('password', PASSWORD_DEFAULT);

        $result = $this->validator->isValid('password', $passwordHash);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS,
            $result->getCode()
        );
        $this->assertNull($result->getPassword());
    }

    public function testPasswordIsValidDoesNotNeedRehashWithAlgorithm()
    {
        $passwordHash = password_hash('password', PASSWORD_ARGON2I);

        $this->validator->setAlgorithm(PASSWORD_ARGON2I);
        $result = $this->validator->isValid('password', $passwordHash);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS,
            $result->getCode()
        );
        $this->assertNull($result->getPassword());
    }

    public function testPasswordIsValidAndIsRehashed()
    {
        $options = array('cost' => 9);
        $passwordHash = password_hash('password', PASSWORD_DEFAULT, $options);
        $this->assertStringStartsWith('$2y$09$', $passwordHash);

        $result = $this->validator->isValid('password', $passwordHash);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $result->getCode()
        );
        $this->assertStringStartsWith('$2y$10$', $result->getPassword());
        // Rehashed password is a valid hash
        $this->assertTrue(password_verify('password', $result->getPassword()));
    }

    public function testCostNineHashValidAndNotRehashedBecauseOptions()
    {
        $options = array('cost' => 9);
        $passwordHash = password_hash('password', PASSWORD_DEFAULT, $options);
        $this->assertStringStartsWith('$2y$09$', $passwordHash);

        $this->validator->setOptions($options);
        $result = $this->validator->isValid('password', $passwordHash);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS,
            $result->getCode()
        );
        $this->assertNull($result->getPassword());
    }

    public function testPasswordIsValidAndIsRehashedBecauseAlgorithm()
    {
        $options = ['cost' => 9];
        $passwordHash = password_hash('password', PASSWORD_DEFAULT, $options);
        $this->assertStringStartsWith('$2y$09$', $passwordHash);

        $this->validator->setAlgorithm(PASSWORD_ARGON2I);
        $result = $this->validator->isValid('password', $passwordHash);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $result->getCode()
        );
        $this->assertStringStartsWith('$argon2i$v=19$m=1024,t=2,p=', $result->getPassword());
        // Rehashed password is a valid hash
        $this->assertTrue(password_verify('password', $result->getPassword()));
    }

    public function testPasswordIsInvalid()
    {
        $passwordHash = password_hash('passwordz', PASSWORD_DEFAULT);

        $result = $this->validator->isValid('password', $passwordHash);

        $this->assertFalse($result->isValid());
        $this->assertEquals(
            ValidationResult::FAILURE_PASSWORD_INVALID,
            $result->getCode()
        );
        $this->assertNull($result->getPassword());
    }

    public function testGetSetOptions()
    {
        $this->assertEquals(array(), $this->validator->getOptions());
        $this->validator->setOptions(array('cost' => '11'));
        $this->assertEquals(array('cost' => '11'), $this->validator->getOptions());
    }
}
