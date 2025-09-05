<?php
/**
 * Part of the "charcoal-dev/http-trust-proxy" package.
 * @link https://github.com/charcoal-dev/http-trust-proxy
 */

declare(strict_types=1);

namespace Charcoal\Http\Tests\TrustProxy;

use Charcoal\Http\TrustProxy\Config\TrustedProxy;
use Charcoal\Http\TrustProxy\TrustGateway;
use Charcoal\Http\Tests\TrustProxy\Fixture\TestEnv;
use PHPUnit\Framework\TestCase;

final class TrustGatewayExtraTest extends TestCase
{
    private function env(
        string  $peerIp,
        ?string $host = null,
        ?int    $port = null,
        ?bool   $https = null,
        ?string $forwarded = null,
        ?string $xff = null,
        ?string $xfProto = null,
        ?string $xfHost = null,
        ?string $xfPort = null
    ): TestEnv {
        return new TestEnv($peerIp, $host, $port, $https, $forwarded, $xff, $xfProto, $xfHost, $xfPort);
    }

    public function testGateway_InvalidPeerIp_ThrowsRuntimeException(): void
    {
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: "not_an_ip",
            host: "hostname.tld",
            https: false
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Invalid peer IP");
        TrustGateway::establishTrust([$proxy], $env);
    }

    public function testGateway_NoProxies_IgnoresHeaders_UsesBaselineAuthority(): void
    {
        $env = $this->env(
            peerIp: "10.1.2.3",
            host: "hostname.tld:8443",
            https: true,
            forwarded: "for=203.0.113.7;proto=http;host=malicious.tld",
            xff: "203.0.113.7, 198.51.100.2"
        );

        $result = TrustGateway::establishTrust([], $env);
        $this->assertSame("10.1.2.3", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertSame(8443, $result->port);
        $this->assertSame("https", $result->scheme);
        $this->assertNull($result->proxyHop);
    }

    public function testGateway_Forwarded_SecondProxyMatches_PromotesAndNormalizes(): void
    {
        $peerIp = "10.1.2.3";
        $proxies = [
            new TrustedProxy(true, ["192.0.2.0/24"]),
            new TrustedProxy(true, ["10.0.0.0/8"]),
        ];
        $env = $this->env(
            peerIp: $peerIp,
            host: "baseline.tld",
            https: false,
            forwarded: "for=10.9.8.7;proto=HTTPS;host=HoStNaMe.TLD, for=203.0.113.7"
        );

        $result = TrustGateway::establishTrust($proxies, $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("https", $result->scheme);
        $this->assertSame(1, $result->proxyHop);
    }

    public function testGateway_Forwarded_TrustedNonHttpProto_IgnoredKeepsBaselineScheme(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "baseline.tld",
            https: false,
            forwarded: "for=10.9.8.7;proto=ftp;host=hostname.tld, for=203.0.113.7"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("http", $result->scheme);
        $this->assertSame(1, $result->proxyHop);
    }

    public function testGateway_Forwarded_Ipv6Trusted_WithHostAndPort_PromotesAll(): void
    {
        $peerIp = "2001:db8::1";
        $proxy = new TrustedProxy(true, ["2001:db8::/32"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "baseline.tld",
            https: false,
            forwarded: "for=\"[2001:db8::2]\";proto=HTTPS;host=\"Client.Example:5443\", for=198.51.100.23"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("198.51.100.23", $result->clientIp);
        $this->assertSame("baseline.tld",   $result->hostname);
        $this->assertNull($result->port);    // baseline (http)
        $this->assertSame("http",           $result->scheme);
        $this->assertSame(1,                $result->proxyHop); // consumed 1 trusted hop
    }

    public function testGateway_Xff_SkipsEmptyAndUnknown_SelectsClient(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "baseline.tld",
            https: false,
            xff: " , unknown, 203.0.113.7, 10.9.8.7, 10.1.2.3"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame(2, $result->proxyHop);
    }

    public function testGateway_Xff_InvalidPortValues_NullPort(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"], protoFromTrustedEdge: true);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            xff: "203.0.113.7, 10.1.2.3",
            xfProto: "https, http",
            xfHost: "client.tld, proxy",
            xfPort: "70000, 80"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame(80, $result->port);
        $this->assertSame("https", $result->scheme);
        $this->assertSame(1, $result->proxyHop);
    }

    public function testGateway_Xff_BracketedIpv6WithPort_SkipsToNextClient(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            xff: "[2001:db8::2]:5000, 203.0.113.7, 10.1.2.3"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame(1, $result->proxyHop);
    }

    public function testGateway_Forwarded_Ipv6Only_Index0_PromotesIpOnly(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            forwarded: "for=\"[2001:db8::4]:51234\";proto=HTTPS;host=malicious.tld"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("2001:db8::4", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("http", $result->scheme);
        $this->assertSame(0, $result->proxyHop);
    }

    public function testGateway_FirstMatchingProxyFailure_DoesNotFallThroughToLaterProxy(): void
    {
        $peerIp = "10.1.2.3";
        $proxies = [
            new TrustedProxy(true, ["10.0.0.0/8"], maxHops: 1),
            new TrustedProxy(true, ["10.0.0.0/8"], maxHops: 5),
        ];
        $env = $this->env(
            peerIp: $peerIp,
            host: "baseline.tld",
            https: false,
            xff: "203.0.113.7, 10.1.2.3"
        );

        $result = TrustGateway::establishTrust($proxies, $env);
        $this->assertSame("10.1.2.3", $result->clientIp);
        $this->assertNull($result->proxyHop);
    }

    public function testGateway_MultipleTrustedProxyEntries_SecondMatchesForwarded(): void
    {
        $peerIp = "198.51.100.9";
        $proxies = [
            new TrustedProxy(true, ["192.0.2.0/24"]),
            new TrustedProxy(true, ["198.51.100.0/24"]),
        ];
        $env = $this->env(
            peerIp: $peerIp,
            host: "baseline.tld",
            https: false,
            forwarded: "for=198.51.100.7;proto=https;host=hostname.tld, for=203.0.113.7"
        );

        $result = TrustGateway::establishTrust($proxies, $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("https", $result->scheme);
        $this->assertSame(1, $result->proxyHop);
    }
}