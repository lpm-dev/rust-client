export function runPhase(kind, scenario, variant, index) {
  return `${kind}-${scenario}-${index}-${variant}`;
}
