<?php

namespace ACAT\JWT;

use Lcobucci\JWT\Token\Plain;

/**
 *
 */
readonly class PlainTokenAdapter implements TokenInterface {

    /**
     * @param   Plain   $token
     * @param   string  $jwt
     */
    public function __construct(
        private Plain $token,
        private string $jwt
    ) {}

    /**
     * @return string|null
     */
    public function getUserId() : ?string
    {
        return $this->getClaim('user_id');
    }

    /**
     * @return string|null
     */
    public function getName() : ?string {
        return $this->getClaim('name');
    }

    /**
     * @return string
     *
     * @param   string  $claim
     */
    public function getClaim(string $claim) : mixed
    {
        return $this->token->claims()->get($claim) ?? null;
    }

    public function getJWT() : string
    {
        return $this->jwt;
    }

}