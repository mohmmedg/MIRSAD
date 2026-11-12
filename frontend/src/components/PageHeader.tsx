import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import styles from "./PageHeader.module.css";

type Props = {
  icon: LucideIcon;
  title: ReactNode;
  description?: ReactNode;
  eyebrow?: ReactNode;
  actions?: ReactNode;
};

export function PageHeader({ icon: Icon, title, description, eyebrow, actions }: Props) {
  return (
    <header className={styles.header}>
      <div className={styles.lead}>
        <span className={styles.chip} aria-hidden="true"><Icon size={20} /></span>
        <div className={styles.text}>
          {eyebrow && <p className={styles.eyebrow}>{eyebrow}</p>}
          <h1 className={styles.title}>{title}</h1>
          {description && <p className={styles.description}>{description}</p>}
        </div>
      </div>
      {actions && <div className={styles.actions}>{actions}</div>}
    </header>
  );
}
