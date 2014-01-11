<?php

/**
 * Password Validator
 *
 * @link      http://github.com/jeremykendall/password-validator Canonical source repo
 * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
 * @license   http://github.com/jeremykendall/password-validator/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Password;

use JeremyKendall\Password\Result as ValidationResult;
use PasswordHash;

/**
 * Validates user's password against phpass
 */
class PhpassValidator implements PasswordValidatorInterface
{
    /**
     * @var array password_hash options
     */
    protected $options = array();

    /**
     * @var array Result info
     */
    protected $resultInfo = array();

    /**
     * @var PasswordHash Used only to check passwords
     */
    protected $hasher;

    /**
     * @var string PHP version
     */
    protected $phpVersion;

    /**
     * Public constructor
     */
    public function __construct()
    {
        $this->phpVersion = PHP_VERSION;
    }

    /**
     * {@inheritDoc}
     */
    public function isValid($password, $passwordHash, $identity = null)
    {
        $this->configureValidator();

        $this->resultInfo = array(
            'code' => ValidationResult::FAILURE_PASSWORD_INVALID,
        );

        $isValid = $this->hasher->CheckPassword($password, $passwordHash);

        if ($isValid === true) {
            $this->resultInfo['code'] = ValidationResult::SUCCESS;
        }

        return new ValidationResult(
            $this->resultInfo['code']
        );
    }

    /**
     * {@inheritDoc}
     */
    public function rehash($password)
    {
        return null;
    }

    public function passwordGetInfo($hash)
    {
        $return = array(
            'algoName' => 'unknown',
            'options' => array(),
        );

        if (substr($hash, 0, 4) === '$2a$' && strlen($hash) == 60) {
            $return['algoName'] = 'blowfish';
            list($cost) = sscanf($hash, "$2a$%d$");
            $return['options']['cost'] = $cost;
        }

        if (substr($hash, 0, 1) === '_' && strlen($hash) == 20) {
            $return['algoName'] = 'extdes';
            $cost = substr($hash, 0, 5);
            $return['options']['cost'] = $cost;
        }

        if (preg_match('/^\$[PH]\$[.\/0-9A-Za-z]{31}$/', $hash) === 1) {
            $return['algoName'] = 'portable';
            $costLog2 = strpos($this->hasher->itoa64, $hash[3]);
            $cost = min($costLog2 - (($this->getPhpVersion() >= '5') ? 5 : 3), 30);
            $return['options']['cost'] = $cost;
        }

        return $return;
    }

    /**
     * {@inheritDoc}
     */
    public function getOptions()
    {
        if (empty($this->options)) {
            $this->options = array(
                'cost' => 8,
                'portable' => false,
            );
        }

        return $this->options;
    }

    /**
     * {@inheritDoc}
     */
    public function setOptions(array $options)
    {
        $this->options = array_merge($this->getOptions(), $options);
    }

    public function isPortable()
    {
        return (version_compare($this->getPhpVersion(), '5.3.0', '<'));
    }

    public function testForPasswordHash()
    {
        if (version_compare($this->getPhpVersion(), '5.3.7', '>=')) {
            trigger_error(
                "Your version of PHP supports password_hash. Please switch to "
                . "JeremyKendall\Password\PasswordValidator",
                E_USER_WARNING
            );
            // @codeCoverageIgnoreStart
        }
        // @codeCoverageIgnoreEnd
    }

    /**
     * Gets the current version of PHP as determined by PHP_VERSION
     *
     * @return string PHP version
     */
    public function getPhpVersion()
    {
        return $this->phpVersion;
    }

    protected function configureValidator()
    {
        $this->testForPasswordHash();
        $options = $this->getOptions();
        // True for PHP versions < 5.3.0
        $portable = $this->isPortable();
        $this->hasher = new PasswordHash($options['cost'], $portable);
    }
}
