import type { KeyboardEvent } from 'react';

/**
 * Arrow/Home/End navigation for a roving-tabindex group (tab bars).
 * Moving focus is enough for tabs — the click handler fires on focus-activate
 * via the browser's own behavior only when the user presses Enter/Space, which
 * the buttons already handle.
 */
export function moveRovingFocus(
  event: KeyboardEvent<HTMLElement>,
  container: HTMLElement | null,
  itemSelector: string,
): void {
  if (!container) return;

  const items = Array.from(container.querySelectorAll<HTMLElement>(itemSelector));
  if (items.length === 0) return;

  const current = items.indexOf(document.activeElement as HTMLElement);
  let next = -1;

  switch (event.key) {
    case 'ArrowRight':
    case 'ArrowDown':
      next = current < 0 ? 0 : (current + 1) % items.length;
      break;
    case 'ArrowLeft':
    case 'ArrowUp':
      next = current < 0 ? items.length - 1 : (current - 1 + items.length) % items.length;
      break;
    case 'Home':
      next = 0;
      break;
    case 'End':
      next = items.length - 1;
      break;
    default:
      return;
  }

  event.preventDefault();
  items[next]?.focus();
}

/** True when the event originated in a field where `/` is ordinary text. */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return (
    tag === 'INPUT' ||
    tag === 'TEXTAREA' ||
    tag === 'SELECT' ||
    target.isContentEditable
  );
}
