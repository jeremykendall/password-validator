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
        $upgradeRehash = password_hash($password, PASSWORD_DEFAULT, array(
            'cost' => 4,
            'salt' => 'CostAndSaltForceRehash',
        ));

        $validatorRehash = password_hash($password, PASSWORD_DEFAULT);

        $result = new ValidationResult(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $validatorRehash
        );

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with($password, $upgradeRehash)
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

    /**
     * This test validates the upgrade scenario proposed in Daniel Karp's blog 
     * post "Rehashing Password Hashes". If the existing persisted password 
     * hash, hashed using the legacy technique, is rehashed with password_hash, 
     * then the UpgradeDecorator can still be used to validate the rehashed 
     * legacy hash and perform a final hash upgrade using the user's plain text 
     * password on the user's next login. 
     *
     * In order to accomplish this scenario, the $validationCallback should be 
     * written to test the hashed plain text password (hashed with the legacy 
     * technique and then rehashed with password_validator) against the 
     * upgraded, persisted hash.
     *
     * @link http://karptonite.com/2014/05/11/rehashing-password-hashes/ Rehashing Password Hashes
     */
    public function testRehashingPasswordHashesScenario()
    {
        $validationCallback = function ($credential, $passwordHash) {
            $legacyHash = hash('sha512', $credential);
            $upgradedLegacyHash = password_hash($legacyHash, PASSWORD_DEFAULT);

            if (password_verify($legacyHash, $upgradedLegacyHash)) {
                return true;
            }

            return false;
        };

        $validator = new UpgradeDecorator(
            $this->decoratedValidator,
            $validationCallback
        );

        $plainTextPassword = 'password';
        $legacyHash = hash('sha512', $plainTextPassword);
        $upgradedLegacyHash = password_hash($legacyHash, PASSWORD_DEFAULT);
        $upgradeValidatorRehash = password_hash(
            $plainTextPassword, 
            PASSWORD_DEFAULT, 
            array(
                'cost' => 4,
                'salt' => 'CostAndSaltForceRehash',
            )
        );
        $finalValidatorRehash = password_hash($plainTextPassword, PASSWORD_DEFAULT);

        $result = new ValidationResult(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $finalValidatorRehash
        );

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with($plainTextPassword, $upgradeValidatorRehash)
            ->will($this->returnValue($result));

        $result = $validator->isValid($plainTextPassword, $upgradedLegacyHash);

        $this->assertTrue($result->isValid());
        $this->assertEquals(
            ValidationResult::SUCCESS_PASSWORD_REHASHED, 
            $result->getCode()
        );

        // Final rehashed password is a valid hash
        $this->assertTrue(
            password_verify($plainTextPassword, $result->getPassword())
        );
    }
}
