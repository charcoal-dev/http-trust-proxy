<?php
/**
 * Part of the "charcoal-dev/http-trust-proxy" package.
 * @link https://github.com/charcoal-dev/http-trust-proxy
 */

declare(strict_types=1);

namespace Charcoal\Http\Tests\TrustProxy\Fixture;

use Charcoal\Http\TrustProxy\Config\ServerEnv;

readonly class TestEnv extends ServerEnv
{
    public function __construct(
        ?string $peerIp,
        ?string $host,
        ?int    $port,
        ?bool   $https,
        public ?string $forwarded,
        public ?string $xff,
        public ?string $xfProto,
        public ?string $xfHost,
        public ?string $xfPort
    ) {
        parent::__construct($peerIp, $host, $port, $https);
    }

    public function getForwardedHeader(string $value = null): ?string
    {
        return $this->forwarded ?? null;
    }

    public function getXForwardedFor(string $value = null): ?string
    {
        return $this->xff ?? null;
    }

    public function getXForwardedHeaders(string $value = null, string $value2 = null, string $value3 = null): array
    {
        return [$this->xfProto ?? null, $this->xfHost ?? null, $this->xfPort ?? null];
    }
}