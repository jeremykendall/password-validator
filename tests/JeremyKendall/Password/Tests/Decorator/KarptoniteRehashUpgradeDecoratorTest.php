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
 * This test validates the upgrade scenario proposed in Daniel Karp's blog
 * post "Rehashing Password Hashes". If the existing persisted password
 * hash, hashed using the legacy technique, is rehashed with password_hash,
 * then the UpgradeDecorator can still be used to validate the rehashed
 * legacy hash and perform a final hash upgrade using the user's plain text
 * password on the user's next login.
 *
 * In order to accomplish this scenario, the $validationCallback should be
 * written to test the hashed plain text password against the upgraded,
 * persisted hash.
 *
 * @link http://karptonite.com/2014/05/11/rehashing-password-hashes/ Rehashing Password Hashes
 */
class KarptoniteRehashUpgradeDecoratorTest extends \PHPUnit_Framework_TestCase
{
    private $decorator;

    private $decoratedValidator;

    private $validationCallback;

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
    }

    public function testRehashingPasswordHashesScenarioCredentialIsValid()
    {
        $plainTextPassword = 'password';
        $salt = mt_rand(1000, 1000000);

        $legacyHash = hash('sha512', $plainTextPassword . $salt);
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

        $validResult = new ValidationResult(
            ValidationResult::SUCCESS_PASSWORD_REHASHED,
            $finalValidatorRehash
        );

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with($plainTextPassword, $upgradeValidatorRehash, $salt)
            ->will($this->returnValue($validResult));

        $result = $this->decorator->isValid(
            $plainTextPassword,
            $upgradedLegacyHash,
            $salt
        );

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

    public function testRehashingPasswordHashesScenarioCredentialIsNotValid()
    {
        $plainTextPassword = 'password';
        $wrongPlainTextPassword = 'i-forgot-my-password';
        $salt = mt_rand(1000, 1000000);

        $legacyHash = hash('sha512', $plainTextPassword . $salt);
        $upgradedLegacyHash = password_hash($legacyHash, PASSWORD_DEFAULT);

        $invalidResult = new ValidationResult(
            ValidationResult::FAILURE_PASSWORD_INVALID
        );

        $this->decoratedValidator->expects($this->never())
            ->method('rehash');

        $this->decoratedValidator->expects($this->once())
            ->method('isValid')
            ->with($wrongPlainTextPassword, $upgradedLegacyHash, $salt)
            ->will($this->returnValue($invalidResult));

        $result = $this->decorator->isValid(
            $wrongPlainTextPassword,
            $upgradedLegacyHash,
            $salt
        );

        $this->assertFalse($result->isValid());
        $this->assertEquals(
            ValidationResult::FAILURE_PASSWORD_INVALID,
            $result->getCode()
        );
    }
}
