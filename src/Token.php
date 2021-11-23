<?php

namespace ACAT\JWT;

use ACAT\JWT\Exception\TokenException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 *
 */
class Token {

    /**
     * @var string
     */
    private string $issuer;

    /**
     * @var int
     */
    private int $expireDate;

    /**
     * @var string
     */
    private string $name;

    /**
     * @var string
     */
    private string $email;

    /**
     * @var string
     */
    private string $accessToken;

    /**
     * @var string
     */
    private string $scopes;

    /**
     * @var string
     */
    private string $userId;

    /**
     * @var array
     */
    private array $config = [];

    /**
     * @var string
     */
    private string $publicKey;

    /**
     * @param array $config
     * @param string $publicKey
     * @throws TokenException
     */
    public function __construct(array $config, string $publicKey) {

        if (!\array_key_exists('issuer', $config)) {
            throw new TokenException('issuer is missing');
        }

        if (!\array_key_exists('scope', $config) || !$config['scope']) {
            throw new TokenException('scope is missing');
        }

        $this->config = $config;
        $this->publicKey = $publicKey;

    }

    /**
     * @param string $token
     * @throws TokenException
     */
    public function createToken(string $token) : void {

        $jwt = (array) JWT::decode($token, new Key($this->getPublicKey(), 'RS256'));

        if (!\array_key_exists('iss', $jwt) || $jwt['iss'] !== $this->config['issuer']) {
            throw new TokenException('invalid issuer');
        }

        if (!\array_key_exists('name', $jwt) || !$jwt['name']) {
            throw new TokenException('name is missing');
        }

        if (!\array_key_exists('email', $jwt) || !$jwt['email']) {
            throw new TokenException('email is missing');
        }

        if (!\array_key_exists('at_hah', $jwt) || !$jwt['at_hah']) {
            throw new TokenException('access token is missing');
        }

        if (!\array_key_exists('scope', $jwt) || !$jwt['scope']) {
            throw new TokenException('no scope defined');
        }

        if (!\array_key_exists('acat:id', $jwt) || !$jwt['acat:id']) {
            throw new TokenException('user id is missing');
        }

        $this->setName($jwt['name']);
        $this->setIssuer($jwt['iss']);
        $this->setEmail($jwt['email']);
        $this->setExpireDate($jwt['exp']);
        $this->setUserId($jwt['acat:id']);
        $this->setAccessToken($jwt['at_hah']);
        $this->setScopes(explode(" ", $jwt['scope']));

    }

    /**
     * @return string
     */
    public function getIssuer(): string {
        return $this->issuer;
    }

    /**
     * @param string $issuer
     * @throws TokenException
     */
    private function setIssuer(string $issuer): void {

        if ($issuer !== $this->config['issuer']) {
            throw new TokenException('issuer verification failed');
        }

        $this->issuer = $issuer;

    }

    /**
     * @return int
     */
    public function getExpireDate(): int {
        return $this->expireDate;
    }

    /**
     * @param int $expireDate
     * @throws TokenException
     */
    private function setExpireDate(int $expireDate): void {

        if (time() > $expireDate) {
            throw new TokenException('token is expired');
        }

        $this->expireDate = $expireDate;

    }

    /**
     * @return string
     */
    public function getName(): string {
        return $this->name;
    }

    /**
     * @param string $name
     */
    private function setName(string $name): void {
        $this->name = $name;
    }

    /**
     * @return string
     */
    public function getEmail(): string {
        return $this->email;
    }

    /**
     * @param string $email
     */
    public function setEmail(string $email): void {
        $this->email = $email;
    }

    /**
     * @return string
     */
    public function getAccessToken(): string {
        return $this->accessToken;
    }

    /**
     * @param string $accessToken
     */
    private function setAccessToken(string $accessToken): void {
        $this->accessToken = $accessToken;
    }

    /**
     * @return array
     */
    public function getScopes(): array {
        return $this->scopes;
    }

    /**
     * @param array $scopes
     * @throws TokenException
     */
    private function setScopes(array $scopes): void {
        foreach ($scopes as $scope) {
            if (!str_contains($this->config['scope'], $scope)) {
                throw new TokenException('scope is not matching');
            }
        }
        $this->scopes = implode(" ", $scopes);
    }

    /**
     * @return string
     */
    public function getUserId(): string {
        return $this->userId;
    }

    /**
     * @param string $userId
     */
    private function setUserId(string $userId): void {
        $this->userId = $userId;
    }

    /**
     * @return string
     */
    public function getPublicKey(): string {
        return file_get_contents($this->publicKey);
    }

}