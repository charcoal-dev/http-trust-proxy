<?php
/**
 * Part of the "charcoal-dev/http-trust-proxy" package.
 * @link https://github.com/charcoal-dev/http-trust-proxy
 */

declare(strict_types=1);

namespace Charcoal\Http\TrustProxy\Config;

/**
 * Represents the server environment, providing details about the client's connection
 * such as IP address, hostname, port, and HTTPS status. It also provides methods
 * to access forwarded headers if they exist.
 */
readonly class ServerEnv
{
    public ?string $peerIp;
    public ?string $hostname;
    public ?int $port;
    public bool $https;

    public function __construct(?string $peerIp = null, ?string $host = null, ?int $port = null, ?bool $https = null)
    {
        $this->peerIp = $peerIp ?? $_SERVER["REMOTE_ADDR"] ?? null;
        $this->hostname = $host ?? $_SERVER["HTTP_HOST"] ?? null;
        $this->port = $port ?? (isset($_SERVER["SERVER_PORT"]) ? intval($_SERVER["SERVER_PORT"]) : null);
        $this->https = $https ?: isset($_SERVER["HTTPS"]) && strtolower($_SERVER["HTTPS"]) === "on";
    }

    /**
     * @return string|null
     */
    public function getForwardedHeader(): ?string
    {
        return $_SERVER["HTTP_FORWARDED"] ?? null;
    }

    /**
     * @return string|null
     */
    public function getXForwardedFor(): ?string
    {
        return $_SERVER["HTTP_X_FORWARDED_FOR"] ?? null;
    }

    /**
     * @return array<string|null>
     */
    public function getXForwardedHeaders(): array
    {
        return [
            $_SERVER["HTTP_X_FORWARDED_PROTO"] ?? null,
            $_SERVER["HTTP_X_FORWARDED_HOST"] ?? null,
            $_SERVER["HTTP_X_FORWARDED_PORT"] ?? null
        ];
    }
}