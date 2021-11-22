<?php

namespace ACAT\JWT;

use Firebase\JWT\JWT;

/**
 *
 */
class Token {

    /**
     * @var string
     */
    private string $issuer;

    /**
     * @var \DateTime
     */
    private \DateTime $expireDate;

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
     * @var array
     */
    private array $scopes;

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
     */
    public function __construct(array $config, string $publicKey) {
        $this->config = $config;
        $this->publicKey = $publicKey;
    }

    public function createToken(string $token) : void {

        $jwt = JWT::decode($token, $this->getPublicKey());

    }


    /**
     * @return string
     */
    private function getPublicKey() : string {
        return fopen('file://' . $this->publicKey);
    }

}