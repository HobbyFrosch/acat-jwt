<?php

namespace ACAT\JWT;

use Exception;
use phpseclib3\Crypt\RSA;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Configuration;
use phpseclib3\Math\BigInteger;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use ACAT\JWT\Exception\TokenException;
use Lcobucci\JWT\Encoding\JoseEncoder;

/**
 *
 */
class TokenDecoder
{

    /**
     * @var string
     */
    private string $realm;

    /**
     * @var string
     */
    private string $authorizationUrl;

    /**
     *
     */
    private const string JWKS_URL = '%s/realms/%s/protocol/openid-connect/certs';

    /**
     * @param   string  $realm
     * @param   string  $authorizationUrl
     */
    public function __construct(string $authorizationUrl, string $realm)
    {
        $this->realm = $realm;
        $this->authorizationUrl = $authorizationUrl;
    }

    /**
     * @throws TokenException
     * @return TokenInterface
     *
     * @param   string  $token
     */
    public function decodeToken(string $token) : TokenInterface {

        $publicKey = $this->getPublicKey($token);

        $config = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($publicKey),
            InMemory::plainText($publicKey)
        );

        /** @var Plain $parsedToken */
        $parsedToken = $config->parser()->parse($token);

        return new PlainTokenAdapter($parsedToken, $token);

    }

    /**
     * @throws TokenException
     * @return string
     *
     * @param   string  $token
     */
    private function getPublicKey(string $token) : string
    {
        $kid = $this->getJwtKid($token);
        return $this->getPemFromJWKS($kid);
    }


    /**
     * @throws TokenException
     * @return string
     *
     * @param   string  $token
     */
    private function getJwtKid(string $token) : string
    {
        $parser = new Parser(new JoseEncoder());
        try {
            $token = $parser->parse($token);
        } catch (Exception $e) {
            throw new TokenException('Fehler: Konnte Token nicht parsen. Ist es ein valides JWT? '.$e->getMessage());
        }
        $kid = $token->headers()->get('kid');
        if (!$kid) {
            throw new TokenException('Fehler: Keine "kid" (Key ID) im Token-Header gefunden.');
        }

        return $kid;
    }


    /**
     * @throws TokenException
     * @return string
     *
     * @param   string  $kid
     */
    private function getPemFromJWKS(string $kid) : string
    {

        if (!$jwks = json_decode(file_get_contents(sprintf(self::JWKS_URL, $this->authorizationUrl, $this->realm)), true)) {
            throw new TokenException('No JWKS :-(');
        }

        foreach ($jwks['keys'] as $key) {
            if ($key['kid'] === $kid && $key['kty'] === 'RSA') {
                $n = $this->base64url_decode($key['n']);
                $e = $this->base64url_decode($key['e']);

                return $this->buildPem($n, $e);
            }
        }
        throw new TokenException("Key mit kid $kid nicht gefunden");
    }

    /**
     * @return string
     *
     * @param   string  $exponent
     * @param   string  $modulus
     */
    private function buildPem(string $modulus, string $exponent) : string
    {
        $mod = new BigInteger($modulus, 256);
        $exp = new BigInteger($exponent, 256);
        $rsa = RSA::loadPublicKey(['n' => $mod, 'e' => $exp]);

        return $rsa->toString('PKCS8');
    }

    /**
     * @return string
     *
     * @param   string  $data
     */
    private function base64url_decode(string $data) : string
    {
        $replaced = strtr($data, '-_', '+/');
        $padded = str_pad($replaced, strlen($replaced) % 4 === 0 ? strlen($replaced) : strlen($replaced) + (4 - strlen($replaced) % 4), '=');

        return base64_decode($padded);
    }

}