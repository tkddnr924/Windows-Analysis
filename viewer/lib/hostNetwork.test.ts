import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { addressOwners, hostNets, ipv4Net, isInternalPeer, isPrivateIpv4, networkAddresses } from "./hostNetwork.ts";

test("addresses come from metadata network entries only, deduplicated in order", () => {
  const metadata = [
    { metadata_id: "n1", kind: "network" },
    { metadata_id: "n2", kind: "network" },
    { metadata_id: "h1", kind: "host" },
  ];
  const addresses = [
    { metadata_id: "n1", ordinal: "1", address: "fe80::1" },
    { metadata_id: "n1", ordinal: "0", address: "192.168.10.16" },
    { metadata_id: "n2", ordinal: "0", address: "192.168.10.16" },
    { metadata_id: "h1", ordinal: "0", address: "10.0.0.9" },
    { metadata_id: "n2", ordinal: "1", address: "" },
  ];
  assert.deepEqual(networkAddresses(metadata, addresses), ["192.168.10.16", "fe80::1"]);
});

test("an address held by several hosts is not forced onto one; loopback never resolves", () => {
  const owners = addressOwners([
    { id: "a", name: "A", ips: ["10.0.0.1", "10.0.0.5", "127.0.0.1"] },
    { id: "b", name: "B", ips: ["10.0.0.5", "10.0.0.2"] },
  ], (ip: string) => ip.startsWith("127."));
  assert.deepEqual(owners.unique.get("10.0.0.1"), { id: "a", name: "A" });
  assert.equal(owners.unique.has("10.0.0.5"), false);
  assert.deepEqual(owners.all.get("10.0.0.5")?.map((host: { id: string }) => host.id), ["a", "b"]);
  assert.equal(owners.all.has("127.0.0.1"), false);
});

test("IPv4 /24 and RFC1918 checks require four valid octets", () => {
  assert.equal(ipv4Net(" 10.0.0.5 "), "10.0.0");
  assert.equal(ipv4Net("10.999.1.1"), null);
  assert.equal(ipv4Net("10.0.0.5 (HOSTA, HOSTB)"), null);
  assert.equal(isPrivateIpv4("10.1.2.3"), true);
  assert.equal(isPrivateIpv4("172.31.0.1"), true);
  assert.equal(isPrivateIpv4("172.32.0.1"), false);
  assert.equal(isPrivateIpv4("10.999.1.1"), false);
  assert.equal(isPrivateIpv4("10.0.0.5.evil"), false);
  assert.deepEqual(hostNets([{ ips: ["203.0.113.4", "bad"] }, { ips: ["203.0.113.9", "198.51.100.1"] }]), ["203.0.113", "198.51.100"]);
});

test("internal classification uses the raw peer address, not the display label", () => {
  const nets = new Set(["203.0.113"]);
  const peer = (address: string) => ({ peer: address, peerKind: "external", peerIsHost: false });
  assert.equal(isInternalPeer(peer("10.0.0.5"), nets), true);
  assert.equal(isInternalPeer(peer("203.0.113.77"), nets), true);
  assert.equal(isInternalPeer(peer("8.8.8.8"), nets), false);
  assert.equal(isInternalPeer({ peer: "HOSTA", peerKind: "host", peerIsHost: true }, nets), true);
  assert.equal(isInternalPeer({ peer: "HOSTA local", peerKind: "local", peerIsHost: false }, nets), true);
});
