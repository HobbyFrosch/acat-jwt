<?php

namespace ACAT\JWT;

/**
 *
 */
interface TokenInterface
{

    /**
     * @return string|null
     */
    public function getUserId() : ?string;

    /**
     * @return string|null
     */
    public function getName() : ?string;

    /**
     * @return mixed
     *
     * @param   string  $claim
     */
    public function getClaim(string $claim) : mixed;

}