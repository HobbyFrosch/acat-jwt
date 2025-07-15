<?php

namespace ACAT\JWT\Exception;

use Throwable;

/**
 *
 */
class TokenException extends \Exception {

    /**
     * @param   string        $message
     * @param   int           $code
     * @param Throwable|null  $previous
     */
    public function __construct(string $message = "", int $code = 401, ?Throwable $previous = null) {
        parent::__construct($message, $code, $previous);
    }

}