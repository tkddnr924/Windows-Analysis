// Input selector labels (docs-04 §0): confirmed drive/label first, then input
// name and collection path, distinguishable even when metadata matches.
// No runtime imports (Node tests).

interface VolumeInfo {
  volume_id: string;
  volume_label: string | null;
  drive_letter: string | null;
  input_name: string | null;
  source_relative: string | null;
  record_count: string;
}

function label(volume: VolumeInfo, pathParts: number | null, withKey: boolean): string {
  const parts = (volume.source_relative ?? "").split(/[\\/]/).filter(Boolean);
  const source = pathParts === null ? parts.join("/") : parts.slice(-pathParts).join("/");
  return [volume.drive_letter, volume.volume_label, volume.input_name, source, `${Number(volume.record_count || 0).toLocaleString()}건`, withKey ? volume.volume_id : ""]
    .filter(Boolean)
    .join(" · ");
}

/** volume_id → label; widens the path, then adds the key, until all differ. */
export function volumeLabels(volumes: VolumeInfo[]): Record<string, string> {
  for (const [pathParts, withKey] of [[3, false], [null, false], [null, true]] as const) {
    const labels = volumes.map((volume) => label(volume, pathParts, withKey));
    if (new Set(labels).size === labels.length || withKey) {
      return Object.fromEntries(volumes.map((volume, index) => [volume.volume_id, labels[index]]));
    }
  }
  return {};
}
