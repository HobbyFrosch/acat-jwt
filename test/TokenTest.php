<?php

namespace Tests;

use ACAT\JWT\Token;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;

/**
 *
 */
class TokenTest extends TestCase {

    /**
     * @test
     * @throws \ACAT\JWT\Exception\TokenException
     */
    public function aTokenCanBeCreated() : void {

        $config = $this->getConfig();
        $jwt = $this->aJWTCanBeCreated();

        $token = new Token($config, 'file://' . __DIR__ . '/resources/public.key');
        $this->assertInstanceOf(Token::class, $token);

    }

    /**
     * @test
     * @return string
     */
    public function aJWTCanBeCreated() : string {

        $jwt = JWT::encode($this->getPayload(), $this->getPrivateKey(), 'RS256');
        $this->assertNotEmpty($jwt);

        return $jwt;

    }

    /**
     * @test
     */
    public function aJWTCanBeDecoded() : void {

        $jwt = $this->aJWTCanBeCreated();
        $this->assertNotEmpty($jwt);

        $payload = (array) JWT::decode($jwt, new Key($this->getPublicKey(), 'RS256'));
        $this->assertIsArray($payload);

        $this->arrayHasKey('iss');
        $this->arrayHasKey('exp');
        $this->arrayHasKey('name');
        $this->arrayHasKey('email');
        $this->arrayHasKey('at_hah');
        $this->arrayHasKey('scope');
        $this->arrayHasKey('acat:id');

        $this->assertEquals('https://foo.de', $payload['iss']);
        $this->assertEquals('User', $payload['name']);
        $this->assertEquals('user@domain.tld', $payload['email']);
        $this->assertEquals('bild', $payload['at_hah']);
        $this->assertEquals('ms path write', $payload['scope']);
        $this->assertEquals('1', $payload['acat:id']);

    }

    private function getConfig(): array {
        return [
            "issuer"    => "https://foo.de",
            "scope" => "ms path write",
        ];
    }

    /**
     * @return array
     */
    private function getPayload(): array {
        return [
            "iss"     => "https://foo.de",
            "exp"     => time() + 10,
            "name"    => "User",
            "email"   => "user@domain.tld",
            "at_hah"  => "bild",
            "scope"   => "ms path write",
            "acat:id" => 1,
        ];
    }

    /**
     * @return string
     */
    private function getPrivateKey(): string {
        return file_get_contents('file://' . __DIR__ . '/resources/private.key');
    }

    private function getPublicKey() : string {
        return file_get_contents('file://' . __DIR__ . '/resources/public.key');
    }

}