import styles from "./StatusDot.module.css";

export type DotState = "idle" | "running" | "completed" | "failed";

export function StatusDot({ state }: { state: DotState }) {
  return <span className={`${styles.dot} ${styles[state]}`} aria-hidden="true" />;
}
