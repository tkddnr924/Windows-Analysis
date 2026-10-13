// Host addresses for the host-connection graph (docs-21): _OVERVIEW Metadata
// network entries (MetadataAddresses) only. No runtime imports (Node tests).

type Cells = Record<string, string | undefined>;

/** Addresses of metadata kind=network entries, in stored order, deduplicated. */
export function networkAddresses(metadata: Cells[], addresses: Cells[]): string[] {
  const network = new Set(metadata.filter((row) => row.kind === "network").map((row) => row.metadata_id));
  const ordered = addresses
    .filter((row) => network.has(row.metadata_id) && (row.address ?? "").trim())
    .sort((a, b) => (a.metadata_id ?? "").localeCompare(b.metadata_id ?? "") || Number(a.ordinal) - Number(b.ordinal));
  return [...new Set(ordered.map((row) => (row.address ?? "").trim()))];
}

export interface HostRef { id: string; name: string }

/**
 * Address → hosts. `unique` holds addresses owned by exactly one host; an
 * address on several hosts stays a candidate and is never forced onto one.
 */
export function addressOwners(hosts: (HostRef & { ips: string[] })[], isLoopback: (address: string) => boolean = () => false) {
  const all = new Map<string, HostRef[]>();
  for (const host of hosts) {
    for (const ip of host.ips) {
      if (isLoopback(ip)) continue;
      const owners = all.get(ip) ?? [];
      if (!owners.some((owner) => owner.id === host.id)) owners.push({ id: host.id, name: host.name });
      all.set(ip, owners);
    }
  }
  const unique = new Map<string, HostRef>();
  for (const [ip, owners] of all) if (owners.length === 1) unique.set(ip, owners[0]);
  return { all, unique };
}

/** Four octets of a strict dotted IPv4 (each 0..255), else null. */
function ipv4Octets(value: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value.trim());
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  return octets.some((octet) => octet > 255) ? null : octets;
}

/** "/24" prefix "a.b.c" of a valid IPv4, else null. */
export function ipv4Net(value: string): string | null {
  const octets = ipv4Octets(value);
  return octets ? octets.slice(0, 3).join(".") : null;
}

/** RFC1918 private IPv4. Malformed addresses are never private. */
export function isPrivateIpv4(value: string): boolean {
  const octets = ipv4Octets(value);
  if (!octets) return false;
  return octets[0] === 10
    || (octets[0] === 192 && octets[1] === 168)
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31);
}

/** Distinct /24 prefixes of the hosts' addresses, in host order. */
export function hostNets(hosts: { ips: string[] }[]): string[] {
  return [...new Set(hosts.flatMap((host) => host.ips.map(ipv4Net).filter((net): net is string => net !== null)))];
}

/** Internal peer: a host, local/loopback, RFC1918, or on a host /24. `peer` is the raw address, not the display label. */
export function isInternalPeer(record: { peer: string; peerKind?: string; peerIsHost?: boolean }, nets: Set<string>): boolean {
  if (record.peerIsHost || record.peerKind === "local" || record.peerKind === "loopback") return true;
  if (isPrivateIpv4(record.peer)) return true;
  const net = ipv4Net(record.peer);
  return net !== null && nets.has(net);
}
