# PhishGuard Demo Package

This package organizes your Aura Build export into demo-ready files.

## Fastest option: open the complete demo

Open:

`PhishGuard_Lite_Complete_Demo.html`

This is the best file for your project demo because it combines the main flows into one browser-openable file:

- Login screen
- Dashboard
- All analysed emails
- Quarantine centre
- Email detail / risk explanation
- Manual email analysis
- Sensitivity settings
- Digest preview
- AI assistant demo

Note: this file uses CDN links for Tailwind, Google Fonts, and Iconify icons. It should be opened with internet access so the styling and icons load correctly.

## Original Aura page exports

Folder:

`static-pages-original-exports/`

This contains the separate HTML pages that Aura generated, cleaned and renamed:

- `login.html`
- `all-emails.html`
- `quarantine.html`
- `email-detail.html`
- `manual-analysis.html`
- `sensitivity-settings.html`
- `digest-preview.html`
- `ai-assistant.html`

Use these only if you want to keep separate pages instead of one combined app.

## React/Vite scaffold

Folder:

`react-vite-login-scaffold/`

This is the React/Vite scaffold from the uploaded files. It currently appears to be a login-only React scaffold, not the full completed Aura app.

To run it:

```bash
cd react-vite-login-scaffold
npm install
npm run dev
```

To build it:

```bash
npm run build
npm run preview
```

For your final demo, use `PhishGuard_Lite_Complete_Demo.html` unless you plan to convert all pages into React components.

## How to export from Aura Build again

In Aura Build, use the project export option and choose HTML export. Aura's public documentation describes HTML export as downloading complete sites with full HTML/CSS/JS files and all pages in one package, suitable for hosting on Netlify, Vercel, or continuing in a code editor.

Recommended workflow:

1. Finalize every page inside Aura.
2. Use Export HTML / Download HTML package.
3. Unzip the exported folder.
4. Check whether Aura gives one combined `index.html` or many separate page HTML files.
5. For a student demo, keep a single main `index.html` if navigation works inside it.
6. For real development, move the UI into a React/Vite project and connect it to your backend/API later.

## Important demo note

This is a frontend prototype. The analysis results, emails, AI assistant replies, login, and quarantine actions are mock/demo interactions unless connected to a backend.

## Version control

This project uses Git for version control. Keep generated dependencies, build outputs, local environment files, logs, and local database files out of commits.
