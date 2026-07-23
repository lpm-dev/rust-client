import { useEffect, useRef } from 'react';
import styles from './ActionDialog.module.css';
import type { ActionPreview } from '../api/types';

interface ActionDialogProps {
  preview: ActionPreview;
  applying: boolean;
  onCancel: () => void;
  onApply: () => void;
}

export function ActionDialog({
  preview,
  applying,
  onCancel,
  onApply,
}: ActionDialogProps) {
  const applyRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    applyRef.current?.focus();
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape' && !applying) onCancel();
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [applying, onCancel]);

  return (
    <div className={styles.backdrop}>
      <div
        className={styles.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby="action-dialog-title"
      >
        <p className={styles.eyebrow}>review planned changes</p>
        <h2 id="action-dialog-title" className={styles.title}>
          {preview.action} {preview.skill}?
        </h2>
        <p className={styles.summary}>
          Nothing changes until you apply this {preview.scope} plan. It expires in{' '}
          {Math.ceil(preview.expiresInSeconds / 60)} minutes.
        </p>

        {preview.securityWarningCount > 0 ? (
          <p className={styles.warning}>
            {preview.securityWarningCount} security{' '}
            {preview.securityWarningCount === 1 ? 'warning requires' : 'warnings require'} review.
          </p>
        ) : null}

        <div className={styles.changes}>
          {preview.changes.length > 0 ? (
            <ul className={styles.changeList}>
              {preview.changes.map((change, index) => (
                <li key={`${change.action}-${change.path}-${index}`}>
                  <span>{change.action}</span>
                  <code>{change.path}</code>
                </li>
              ))}
            </ul>
          ) : (
            <p className={styles.empty}>No filesystem changes are required.</p>
          )}

          {preview.updates.map((update, index) =>
            typeof update.diff === 'string' ? (
              <pre key={`${update.name ?? 'update'}-${index}`} className={styles.diff}>
                {update.diff}
              </pre>
            ) : null,
          )}
        </div>

        <div className={styles.actions}>
          <button
            type="button"
            className={styles.cancel}
            disabled={applying}
            onClick={onCancel}
          >
            cancel
          </button>
          <button
            ref={applyRef}
            type="button"
            className={styles.apply}
            disabled={applying}
            onClick={onApply}
          >
            {applying ? 'applying…' : `apply ${preview.action}`}
          </button>
        </div>
      </div>
    </div>
  );
}
