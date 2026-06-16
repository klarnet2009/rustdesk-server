# Extension Guide

## How to Add a New Page to the Web Panel

Follow these steps to add a new view (e.g. `Reports` page) to the panel:

### Step 1: Update Nav Links in BASE_HTML
Open `server.py`, find the template string `BASE_HTML`, and append a new list item to the navbar sidebar list:
```html
<li>
    <a class="{{ 'active bg-primary text-primary-content font-semibold' if active_page == 'reports' else '' }}" href="{{ url_for('web_reports') }}">
        <i data-lucide="bar-chart-2" class="w-5 h-5" aria-hidden="true"></i>
        Reports
    </a>
</li>
```

### Step 2: Define the HTML Template constant
Add a new template constant (e.g. `REPORTS_HTML`) under the `TEMPLATES` comment block:
```python
REPORTS_HTML = r'''
{% extends "base" %}
{% block content %}
<h1 class="text-2xl font-bold text-base-content text-balance mb-6">Reports</h1>
<div class="card bg-base-100 border border-base-300 shadow-sm">
    <div class="card-body p-6">
        <p class="text-base-content/80">Report content goes here…</p>
    </div>
</div>
{% endblock %}
'''
```

### Step 3: Implement the Route Controller
Define a new Flask routing function:
```python
@app.route('/reports')
@web_login_required
def web_reports():
    # Fetch parameters or write logic here
    return render_page(REPORTS_HTML, title="Reports", active_page="reports")
```

### Step 4: Verify Compilation and UI Compliance
1. Run `python -m py_compile server.py` to check for syntax issues.
2. Verify that any buttons, tables, or fields added meet the [Coding Standards](file:///D:/rustdesk_src/docs/development/coding-standards.md) (accessible labels, tabular numbers, correct headers, loaders).
