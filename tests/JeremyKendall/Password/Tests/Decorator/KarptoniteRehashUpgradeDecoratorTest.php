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

/**
 * This test validates the upgrade scenario outlined in Daniel Karp's blog post
 * {@link http://bit.ly/T0gwRN "Rehashing Password Hashes"}.
 *
 * In order to properly validate this scenario, the $validationCallback should
 * be written to use {@link http://php.net/password_verify password_verify} to
 * test the plain text password's legacy hash against the upgraded, persisted
 * hash.
 */
class KarptoniteRehashUpgradeDecoratorTest extends \PHPUnit_Framework_TestCase
{
    private $decorator;
    private $decoratedValidator;
    private $validationCallback;
    private $plainTextPassword;
    private $legacySalt;
    private $upgradedLegacyHash;

    protected function setUp()
    {
        parent::setUp();

        $this->validationCallback = function ($credential, $passwordHash, $salt) {
            // Recreate the legacy hash. This was the persisted password hash
            // prior to upgrading.
            $legacyHash = hash('sha512', $credential . $salt);

            // Now test the old hash against the new, upgraded hash
            if (password_verify($legacyHash, $passwordHash)) {
                return true;
            }

            return false;
        };

        $interface = 'JeremyKendall\Password\PasswordValidatorInterface';
        $this->decoratedValidator = $this->getMockBuilder($interface)
            ->disableOriginalConstructor()
            ->getMock();

        $this->decorator = new UpgradeDecorator(
            $this->decoratedValidator,
            $this->validationCallback
        );

        $this->plainTextPassword = 'password';
        $this->legacySalt = mt_rand(1000, 1000000);

        $legacyHash = hash('sha512', $this->plainTextPassword . $this->legacySalt);
        $this->upgradedLegacyHash = password_hash($legacyHash, PASSWORD_DEFAULT);
    }

    public function testRehashingPasswordHashesScenarioCredentialIsValid()
    {
        $finalValidatorRehash = password_hash($this->plainTextPassword, PASSWORD_DEFAULT);

        $validResult = new ValidationResult(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $finalValidatorRehash
        );

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with($this->plainTextPassword, $this->isType('string'), $this->legacySalt)
            ->will($this->returnValue($validResult));

        $result = $this->decorator->isValid(
            $this->plainTextPassword,
            $this->upgradedLegacyHash,
            $this->legacySalt
        );

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $result->getCode()
        );

        // Final rehashed password is a valid hash
        $this->assertTrue(
            password_verify($this->plainTextPassword, $result->getPassword())
        );
    }

    public function testRehashingPasswordHashesScenarioCredentialIsNotValid()
    {
        $wrongPlainTextPassword = 'i-forgot-my-password';

        $invalidResult = new ValidationResult(
            ValidationResult::FAILURE_PASSWORD_INVALID
        );

        $this->decoratedValidator->expects($this->never())
            ->method('rehash');

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with($wrongPlainTextPassword, $this->upgradedLegacyHash, $this->legacySalt)
            ->will($this->returnValue($invalidResult));

        $result = $this->decorator->isValid(
            $wrongPlainTextPassword,
            $this->upgradedLegacyHash,
            $this->legacySalt
        );

        $this->assertFalse($result->isValid());
        $this->assertEquals(
            ValidationResult::FAILURE_PASSWORD_INVALID,
            $result->getCode()
        );
    }

    /**
     * @dataProvider callbackDataProvider
     */
    public function testVerifyValidationCallback($password, $result)
    {
        $isValid = call_user_func(
            $this->validationCallback,
            $password,
            $this->upgradedLegacyHash,
            $this->legacySalt
        );

        $this->assertEquals($result, $isValid);
    }

    public function callbackDataProvider()
    {
        return array(
            array('password', true),
            array('wrong-password', false),
        );
    }
}
