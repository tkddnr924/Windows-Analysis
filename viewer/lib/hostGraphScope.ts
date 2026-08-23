/**
 * Select the relationship set represented by the graph and its adjacent
 * inspector.  Keeping this independent of the React renderer makes it harder
 * to accidentally draw one host while listing another host's evidence.
 */
export function graphEdgesForScope<T extends { host: string; peer: string }>(
  edges: T[],
  focus: string | null,
  overall: boolean,
): T[] {
  if (overall || !focus) return edges;
  return edges.filter((edge) =>
    edge.host.toLocaleLowerCase() === focus ||
    edge.peer.toLocaleLowerCase() === focus
  );
}
