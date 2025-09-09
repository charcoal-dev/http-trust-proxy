<?php
/**
 * Part of the "charcoal-dev/http-trust-proxy" package.
 * @link https://github.com/charcoal-dev/http-trust-proxy
 */

declare(strict_types=1);

namespace Charcoal\Http\TrustProxy;

use Charcoal\Http\TrustProxy\Config\ServerEnv;
use Charcoal\Http\TrustProxy\Config\TrustedProxy;
use Charcoal\Http\TrustProxy\Result\TrustGatewayResult;
use Charcoal\Net\Dns\HostnameHelper;

/**
 * TrustGateway is a final readonly class responsible for handling trusted
 * proxy configurations, validating incoming server requests, and extracting
 * client-related information such as IP address, hostname, port, and scheme.
 */
final readonly class TrustGateway
{
    /**
     * @param array $proxies
     * @param ServerEnv $env
     * @return TrustGatewayResult
     */
    public static function establishTrust(array $proxies, ServerEnv $env = new ServerEnv()): TrustGatewayResult
    {
        $peerIpBinary = @inet_pton($env->peerIp ?? "");
        if ($peerIpBinary === false) {
            throw new \RuntimeException("Invalid peer IP: " . $env->peerIp);
        }

        $port = $env->port;
        $hostname = $env->hostname;
        $scheme = $env->https ? "https" : "http";
        $checkTrustedProxies = self::checkProxies($peerIpBinary, $proxies, $env);
        if ($checkTrustedProxies) {
            $clientIp = $checkTrustedProxies[0];
            $hostname = $checkTrustedProxies[1] ?: $hostname;
            $port = $checkTrustedProxies[2] ?: $port;
            $scheme = $checkTrustedProxies[3] ?: $scheme;
            $proxyHop = $checkTrustedProxies[4];
            $proxy = $checkTrustedProxies[5];
        } else {
            $clientIp = $env->peerIp;
            $proxyHop = null;
            $proxy = null;
        }

        if (!$proxy) {
            // Validation default values only; Proxy returns pre-validated data
            [$defaultHost, $suggestedPort] = HostnameHelper::normalizeHostnamePort($hostname) ?: [null, null];
            $port = $port ?? $suggestedPort;
            $hostname = $defaultHost;
        }

        return new TrustGatewayResult($proxy, $proxyHop, $clientIp, $hostname, $port, $scheme);
    }

    /**
     * @param string $peerIpBinary
     * @param TrustedProxy[] $proxies
     * @param ServerEnv $env
     * @return array<string,string|null,int|null,string|null,int,TrustedProxy>|false
     */
    private static function checkProxies(string $peerIpBinary, array $proxies, ServerEnv $env): array|false
    {
        if (!$proxies) {
            return false;
        }

        // Convert literal to binary form
        $matched = false;
        foreach ($proxies as $proxy) {
            $matched = $proxy->match($peerIpBinary);
            if ($matched) {
                break;
            }
        }

        if (!$matched || !isset($proxy)) {
            return false;
        }

        // User "Forwarded" header if available, and enabled
        if ($proxy->useForwarded) {
            $forwarded = $env->getForwardedHeader();
            if ($forwarded) {
                $matched = self::checkForwarded($proxy, $forwarded, $proxy->maxHops);
                if ($matched) {
                    return [...$matched, $proxy];
                }
            }
        }

        $xff = self::checkXFF($proxy, $env, $proxy->maxHops);
        if (!$xff) {
            return false;
        }

        [$clientIp, $hostname, $port, $scheme, $proxyHop] = $xff;
        $scheme = $scheme && in_array(strtolower($scheme), ["http", "https"]) ?
            $scheme : null;

        if (is_string($port) && ctype_digit($port)) {
            $port = (int)$port;
        }

        if ($port && ($port < 1 || $port > 65535)) {
            $port = null;
        }

        if ($hostname) {
            $hostname = HostnameHelper::normalizeHostnamePort($hostname) ?: [null, null];
            if ($hostname) {
                $port = $port ?? $hostname[1] ?? null;
                $hostname = $hostname[0] ?? null;
            }
        }

        return [$clientIp, $hostname, $port, $scheme, $proxyHop, $proxy];
    }

    /**
     * @param TrustedProxy $proxy
     * @param ServerEnv $env
     * @param int $maxHops
     * @return array|false
     */
    private static function checkXFF(TrustedProxy $proxy, ServerEnv $env, int $maxHops): array|false
    {
        $xff = $env->getXForwardedFor();
        if (!$xff) {
            return false;
        }

        $clientIp = null;
        $ips = array_reverse(array_map(fn($a) => trim($a, " \t\"'"), explode(",", $xff)));
        if (!$ips) {
            return false;
        }

        $index = -1;
        foreach ($ips as $ip) {
            $index++;
            if ($index >= $maxHops) {
                break;
            }

            $ip = trim($ip);
            if ($ip === "" || strcasecmp($ip, "unknown") === 0) {
                continue;
            }

            // Strip IPv4 ":port" if present (inet_pton can't handle it)
            if (preg_match("/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/", $ip)) {
                $ip = strstr($ip, ":", true);
            }

            $ipBinary = @inet_pton($ip);
            if ($ipBinary === false) {
                continue;
            }

            if (!$proxy->match($ipBinary)) {
                $clientIp = $ip;
                break;
            }
        }

        if (!$clientIp) {
            return false;
        }

        $xffData = $env->getXForwardedHeaders();
        $protoRev = array_reverse(array_map("trim", explode(",", $xffData[0] ?? "")));
        $hostRev = array_reverse(array_map("trim", explode(",", $xffData[1] ?? "")));
        $portRev = array_reverse(array_map("trim", explode(",", $xffData[2] ?? "")));
        $protoOrig = array_map("trim", explode(",", $xffData[0] ?? ""));
        if ($index === 0) {
            $scheme = $proxy->protoFromTrustedEdge ? ($protoOrig[0] ?? null) : null;
            return [$clientIp, null, null, $scheme, 0];
        }

        $trustedIndex = max(0, $index - 1);
        $host = $hostRev[$trustedIndex] ?? null;
        $port = $portRev[$trustedIndex] ?? null;
        $scheme = $proxy->protoFromTrustedEdge
            ? ($protoOrig[0] ?? null)
            : ($protoRev[$trustedIndex] ?? null);
        return [$clientIp, $host, $port, $scheme, $index];
    }

    /**
     * @param TrustedProxy $proxy
     * @param string $header
     * @param int $maxHops
     * @return array<string,string|null,int|null,string|null,int>|false
     */
    private static function checkForwarded(TrustedProxy $proxy, string $header, int $maxHops): array|false
    {
        if (!$header) {
            return false;
        }

        $hostname = null;
        $port = null;
        $scheme = null;
        $entries = ForwardedHeaderParser::getProxies($header, $maxHops) ?: [];
        $index = -1;
        foreach ($entries as $channel) {
            $index++;
            if (!isset($channel["for"])) {
                continue;
            }

            $channelIp = (HostnameHelper::normalizeHostnamePort($channel["for"]) ?: [null])[0];
            if (!$channelIp) {
                continue;
            }

            $channelIpBinary = @inet_pton($channelIp);
            if ($channelIpBinary === false) {
                continue;
            }

            if (!$proxy->match($channelIpBinary)) {
                if ($index === 0) {
                    return [$channelIp, null, null, null, 0];
                }

                return [$channelIp, $hostname ?? null, $port ?? null, $scheme ?? null, $index];
            }

            if (isset($channel["host"])) {
                [$entryHost, $entryPort] = HostnameHelper::normalizeHostnamePort($channel["host"]) ?: [null, null];
                if ($entryHost) {
                    $hostname = $entryHost;
                    $port = $entryPort;
                }
            }

            if (isset($channel["proto"]) && in_array(strtolower($channel["proto"]), ["http", "https"])) {
                $scheme = $channel["proto"];
            }
        }

        return false;
    }
}