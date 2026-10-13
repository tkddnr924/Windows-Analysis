import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { addressOwners, networkAddresses } from "./hostNetwork.ts";

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
