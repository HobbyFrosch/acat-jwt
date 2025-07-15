<?php

namespace ACAT\JWT;

use ACAT\JWT\Exception\TokenException;

/**
 *
 */
class TokenAuthorizer
{

    /**
     *
     */
    private const string CLAIM_RESOURCE_ACCESS = 'resource_access';

    /**
     * @throws TokenException
     * @return bool
     *
     * @param   string|null     $requiredRole
     * @param   TokenInterface  $token
     * @param   string          $resourceName
     */
    public function authorize(TokenInterface $token, string $resourceName, string $requiredIssuer, ?string $requiredRole = null) : bool {

        $resourceOwner = $token->getClaim(self::CLAIM_RESOURCE_ACCESS);

        if (!is_array($resourceOwner) || !array_key_exists($resourceName, $resourceOwner)) {
            throw new TokenException("Resource '{$resourceName}' not found in token");
        }

        if ($requiredRole === null) {
            return true;
        }

        $roles = $resourceAccess[$resourceName]['roles'] ?? [];

        if (!is_array($roles)) {
            throw new TokenException("Roles are missing or malformed for '{$resourceName}'");
        }

        return in_array($requiredRole, $roles, true);

    }

}