// Types shared by every dashboard script. The scripts are plain global scripts
// (no imports): they are concatenated into one bundle in index.html order, so
// a declaration here is visible to all of them and emits no code.

/**
 * A JSON response of this server. Its shape is enforced on the server (every
 * report is built and validated in zanjir/); the dashboard reads it as dynamic
 * data. This alias is the one deliberate `any` of the code base: everything
 * the dashboard itself computes is typed.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ApiData = any;

/**
 * An element looked up by id. The ids are fixed in index.html and the code
 * reads the form-control properties it knows each one has (value, checked,
 * disabled, options ...): the intersection gives exactly those properties
 * without a cast at every call site.
 */
type Field = HTMLInputElement & HTMLSelectElement & HTMLTextAreaElement &
  Pick<HTMLFormElement, 'elements' | 'reset' | 'requestSubmit' | 'checkValidity'>;

interface DashboardState {
  busy: boolean;
  repository: ApiData | null;
  reviews: Record<string, ApiData>;
  projects: ApiData[];
  project: string;
}


// ---- DOM declarations the dashboard relies on -------------------------------
// Every querySelector in these scripts looks inside markup the same function
// has just rendered, so the element exists: the result is typed as present
// and as a form-capable element instead of `Element | null` at ~300 sites.
interface ParentNode {
  querySelector<E extends Element = Field>(selectors: string): E;
  querySelectorAll<E extends Element = Field>(selectors: string): NodeListOf<E>;
}
interface Element {
  closest<E extends Element = Field>(selectors: string): E | null;
}
// The dashboard's own events: which view became visible, and "a target was
// registered or removed".
interface DocumentEventMap {
  'view-shown': CustomEvent<string>;
  'registry-changed': CustomEvent<unknown>;
}
// Named controls of a form, e.g. form.elements.username.
interface HTMLFormControlsCollection {
  readonly [name: string]: Field;
}
// Every form in the dashboard has text controls only (no file inputs), so a
// present field is a string; an absent one is read as ''.
interface FormData {
  get(name: string): string;
}

// Shared between shell.ts (which defines them) and the section scripts.
interface Window {
  openModal(title: string, html: string, onReady?: (box: Field) => void): void;
  closeModal(): void;
}

// WebMCP (experimental): the dashboard offers its scans as tools to an in-browser
// agent when the browser provides document.modelContext.
interface Document {
  modelContext?: { registerTool?(tool: ApiData, options?: { signal?: AbortSignal }): unknown };
}
