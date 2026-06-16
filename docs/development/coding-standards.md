# Coding Standards

## 1. Frontend Development

### Styling Standard
* Never use raw CSS style overrides. All classes must derive from Tailwind CSS or DaisyUI component classes (`.btn`, `.input`, `.table`, `.select`).
* The source styling is managed strictly inside `src/input.css` and compiled using `npm run build` to `/static/output.css`.

### Vercel Web Interface Guidelines Compliance
All new UI components must strictly follow these rules:
1. **Interactive Focus**: Ensure every button and input has visible focus states (e.g. `focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-none`).
2. **Icons**: Use Lucide icons. Every icon tag must have `aria-hidden="true"`.
3. **Form Formatting**: Placeholders must end with `…` and provide a clear pattern example (e.g. `e.g. admin`).
4. **Number columns**: Use the `.tabular-nums` class on every text containing numerical listings, counters, IP addresses, versions, and times.
5. **Headings**: Title headings on the same page must remain hierarchical (e.g. using `h1` for titles, `h2` for sub-cards). Enable `text-balance` (or `text-wrap: balance`) on all title elements to prevent widows.
6. **Spellcheck**: Turn spellcheck off (`spellcheck="false"`) for security codes, emails, bind user accounts, and username inputs.

## 2. Python Backend
* Run Python 3.x syntax.
* Implement thread-safe database connections using context managers or discrete calls to `get_db()`.
* Parameterize all SQLite queries to avoid SQL Injection vulnerability.
* Output logs with `datetime.utcnow()` when verifying actions or auditing connections.
