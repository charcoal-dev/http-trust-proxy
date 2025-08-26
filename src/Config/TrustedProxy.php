<?php
/*
 * Part of the "charcoal-dev/http-trust-proxy" package.
 * @link https://github.com/charcoal-dev/http-trust-proxy
 */

declare(strict_types=1);

namespace Charcoal\Http\TrustProxy\Config;

use Charcoal\Net\Cidr\CidrHelper;

/**
 * Represents a trusted proxy configuration that validates if a given binary IP
 * address matches specific allowed CIDR ranges. This class is designed to
 * handle proxy-related operations and validation logic.
 * @property-read bool $useForwarded Indicates whether the "Forwarded" header should be used.
 * @property-read array<string,array{string,string}> $allowedCidr Contains the validated list of allowed CIDR blocks.
 */
readonly class TrustedProxy
{
    /** @var array<string,array{string,string}> */
    private array $allowedCidr;

    public function __construct(
        public bool $useForwarded,
        array       $cidrList,
        public int  $maxHops = 6,
        public bool $protoFromTrustedEdge = false
    )
    {
        $cidrCount = count($cidrList);
        if ($cidrCount < 1) {
            throw new \InvalidArgumentException("At least one CIDR must be provided");
        }

        $this->allowedCidr = CidrHelper::parseCidrListToBinary($cidrList);
        if (count($this->allowedCidr) !== $cidrCount) {
            throw new \InvalidArgumentException("One or more CIDR blocks are invalid");
        }
    }

    /**
     * @return string
     * @api
     */
    public function checksum(): string
    {
        return md5(serialize($this->allowedCidr), true);
    }

    /**
     * Determines if the given binary IP address matches any network ranges in the allowed CIDR list.
     */
    public function match(string $ipBinary): bool
    {
        foreach ($this->allowedCidr as $network) {
            if (CidrHelper::ipInCidrBinary($ipBinary, true, $network[0], $network[1])) {
                return true;
            }
        }

        return false;
    }
}