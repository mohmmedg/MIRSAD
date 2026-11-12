import { Component, type CSSProperties, type ErrorInfo, type ReactNode } from "react";
import { safeUserError } from "../utils/security";

interface Props {
  children: ReactNode;
  /** Short label shown in the fallback UI so it's clear which region crashed
   * (e.g. "التقارير" vs the whole app). */
  label?: string;
  /** If true, only this subtree is replaced by the fallback on error instead
   * of a full-page message — use for a single panel/page, not the app root. */
  inline?: boolean;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * Without this, an uncaught render error anywhere in the tree unmounts the
 * ENTIRE React app (topbar, sidebar, everything) instead of just the
 * component that failed — this is what previously showed up as a totally
 * blank page after generating a report with unexpected data.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(_error: Error, _info: ErrorInfo) {
    // eslint-disable-next-line no-console
    console.error(`[ErrorBoundary${this.props.label ? `:${this.props.label}` : ""}] render failure`);
  }

  private reset = () => this.setState({ hasError: false, error: null });

  render() {
    if (!this.state.hasError) return this.props.children;

    const style: CSSProperties = this.props.inline
      ? { padding: "1.5rem", border: "1px solid var(--sev-critical)", borderRadius: 8, background: "var(--sev-critical-dim)", margin: "1rem 0" }
      : { display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "100vh", padding: "2rem", textAlign: "center", gap: "0.75rem" };

    return (
      <div style={style}>
        <strong>{this.props.label ? `حدث خطأ غير متوقع بـ ${this.props.label}` : "حدث خطأ غير متوقع"}</strong>
        <span style={{ opacity: 0.75, fontSize: "0.85rem" }}>{safeUserError(this.state.error, "حدث خطأ غير متوقع. يرجى إعادة المحاولة.")}</span>
        <button type="button" onClick={this.reset} style={{ marginTop: "0.5rem" }}>
          إعادة المحاولة
        </button>
      </div>
    );
  }
}
