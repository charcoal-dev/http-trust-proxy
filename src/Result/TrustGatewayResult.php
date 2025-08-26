<?php
/**
 * Part of the "charcoal-dev/http-trust-proxy" package.
 * @link https://github.com/charcoal-dev/http-trust-proxy
 */

declare(strict_types=1);

namespace Charcoal\Http\TrustProxy\Result;

use Charcoal\Http\TrustProxy\Config\TrustedProxy;

/**
 * Represents the result of processing a trusted gateway.
 * This class encapsulates information about a trusted proxy, including
 * details about the hostname, port, scheme, and proxy hop related to
 * the gateway request.
 */
final readonly class TrustGatewayResult
{
    public function __construct(
        public ?TrustedProxy $proxy,
        public ?int          $proxyHop,
        public string        $clientIp,
        public string        $hostname,
        public ?int          $port,
        public ?string       $scheme,
    )
    {
    }
}