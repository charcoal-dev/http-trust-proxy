<?php

declare(strict_types=1);

namespace Charcoal\Http\Tests\TrustProxy;

use Charcoal\Http\TrustProxy\Config\TrustedProxy;
use Charcoal\Http\TrustProxy\TrustGateway;
use Charcoal\Http\Tests\TrustProxy\Fixture\TestEnv;
use PHPUnit\Framework\TestCase;

/**
 * Class TrustGatewayTest
 * @package Charcoal\Http\Tests\TrustProxy
 */
final class TrustGatewayTest extends TestCase
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

    public function testGateway_Forwarded_QuotedTokens_MixedCaseProto_PromotesAndLowercases(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            forwarded: 'for=10.9.8.7;proto="HTTPS";host="hostname.tld", for=203.0.113.7'
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("https", $result->scheme);
        $this->assertSame(1, $result->proxyHop);
    }

    public function testGateway_Xff_Ipv4WithPort_StripsPortAndKeepsBaselineAuthority(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            xff: "203.0.113.7:51111, 10.1.2.3"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("http", $result->scheme);
        $this->assertSame(1, $result->proxyHop);
    }

    public function testGateway_Forwarded_TrustedThenClient_UsesLastTrustedAuthority(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            forwarded: "for=10.9.8.7;proto=https;host=hostname.tld, for=203.0.113.7"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("https", $result->scheme);
        $this->assertSame(1, $result->proxyHop);
    }

    public function testGateway_Forwarded_AllTrusted_NoPromotion(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            forwarded: "for=10.2.3.4, for=10.3.4.5"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame($peerIp, $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("http", $result->scheme);
    }

    public function testGateway_Forwarded_PeerUntrusted_IgnoresHeader(): void
    {
        $peerIp = "192.0.2.10";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            forwarded: "for=203.0.113.7;proto=https;host=hostname.tld"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame($peerIp, $result->clientIp);
        $this->assertSame("http", $result->scheme);
    }

    public function testGateway_Forwarded_InvalidAndObfuscated_SkipsUntilValid(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            forwarded: "for=_hidden, for=garbage, for=203.0.113.7"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame(2, $result->proxyHop);
    }

    public function testGateway_Forwarded_Ipv6Index0_PromotesIpOnly(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            forwarded: 'for="[2001:db8::2]:51234";proto=https;host=malicious.tld'
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("2001:db8::2", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("http", $result->scheme);
        $this->assertSame(0, $result->proxyHop);
    }

    public function testGateway_Xff_BasicTwoHops_PromotesClientKeepsBaselineAuthority(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            xff: "203.0.113.7, 10.1.2.3"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("http", $result->scheme);
        $this->assertSame(1, $result->proxyHop);
    }

    public function testGateway_Xff_RightAligned_UsesNearestTrustedAuthority_Short(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            xff: "203.0.113.7, 10.9.8.7, 10.1.2.3",
            xfProto: "http, https, http",
            xfHost: "client.tld, hostname.tld, proxyA",
            xfPort: "1234, 443, 80"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertSame(443, $result->port);
        $this->assertSame("https", $result->scheme);
        $this->assertSame(2, $result->proxyHop);
    }

    public function testGateway_Xff_MaxHopsCap_NoPromotionBeyondCap(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"], maxHops: 1);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            xff: "203.0.113.7, 10.9.8.7, 10.1.2.3"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame($peerIp, $result->clientIp);
    }

    public function testGateway_BothHeaders_ForwardedWinsOverXff(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            forwarded: "for=10.9.8.7;proto=https;host=hostname.tld, for=203.0.113.7",
            xff: "203.0.113.88, 10.9.8.7, 10.1.2.3",
            xfProto: "http, http, http",
            xfHost: "client.tld, proxyB, proxyA",
            xfPort: "1234, 80, 80"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.7", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertNull($result->port);
        $this->assertSame("https", $result->scheme);
        $this->assertSame(1, $result->proxyHop);
    }

    public function testGateway_Xff_AllTrusted_NoPromotion(): void
    {
        $peerIp = "10.1.2.3";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            xff: "10.2.3.4, 10.1.2.3"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame($peerIp, $result->clientIp);
    }

    public function testGateway_Xff_UntrustedPeer_IgnoresXff(): void
    {
        $peerIp = "192.0.2.10";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"]);
        $env = $this->env(
            peerIp: $peerIp,
            host: "hostname.tld",
            https: false,
            xff: "203.0.113.7, 10.1.2.3"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame($peerIp, $result->clientIp);
        $this->assertSame("http", $result->scheme);
    }

    public function testGateway_Xff_LongChain_Index7_UsesNearestTrustedAndCustomPort(): void
    {
        $peerIp = "10.0.0.99";
        $proxy = new TrustedProxy(true, ["10.0.0.0/8"], maxHops: 10);
        $env = $this->env(
            peerIp: $peerIp,
            xff: "garbage, unknown, 203.0.113.77, 10.0.0.93, 10.0.0.94, 10.0.0.95, 10.0.0.96, 10.0.0.97, 10.0.0.98, 10.0.0.99",
            xfProto: "http, http, http, https, http, http, http, http, http, http",
            xfHost: "h0, h1, h2, hostname.tld, h4, h5, h6, h7, h8, h9",
            xfPort: "5000, 5001, 5002, 6001, 5004, 5005, 5006, 5007, 5008, 5009"
        );

        $result = TrustGateway::establishTrust([$proxy], $env);
        $this->assertSame("203.0.113.77", $result->clientIp);
        $this->assertSame("hostname.tld", $result->hostname);
        $this->assertSame(6001, $result->port);
        $this->assertSame("https", $result->scheme);
        $this->assertSame(7, $result->proxyHop);
    }
}