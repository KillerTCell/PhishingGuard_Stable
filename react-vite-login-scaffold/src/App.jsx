import { useState, useRef } from 'react';

// =====================================================
// TEMPORARY DEMO DATA — FRONTEND TESTING ONLY
// Replace this section with backend API responses before production.
// =====================================================

// Real passwords must never be stored in frontend code. These accounts exist
// solely so the frontend can be tested before POST /api/auth/login is live.
const DEMO_USERS = [
  { role: 'Admin',   email: 'admin@phishguard.test',   password: 'admin123',   name: 'Security Admin'   },
  { role: 'Analyst', email: 'analyst@phishguard.test', password: 'analyst123', name: 'Security Analyst' },
];

// Production API replacement points:
// POST /api/auth/login          — validate credentials, issue session/token
// POST /api/auth/register       — validate, hash password, assign lowest-privilege role
// POST /api/auth/forgot-password — generate secure token, send email (generic response)
// POST /api/auth/logout          — invalidate session/token server-side
//
// The backend must handle password hashing, validation, session/token issuing,
// role-based access control, password reset tokens, audit logging,
// and protected API access. Never allow the frontend to assign the Admin role.

// ─── Auth helpers ────────────────────────────────────────────────────────────

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Simulates a brief network round-trip for demo realism.
function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─── Demo auth stubs ─────────────────────────────────────────────────────────

async function loginUser(credentials, sessionUsers) {
  // Temporary frontend demo login only.
  // Replace this with POST /api/auth/login before production.
  // Real passwords must never be stored in frontend code.
  await wait(350);
  const allUsers = [...DEMO_USERS, ...sessionUsers];
  return allUsers.find(
    u =>
      u.email.toLowerCase() === credentials.email.toLowerCase() &&
      u.password === credentials.password,
  ) || null;
}

// ─── Spinner icon (inline so no extra dep) ───────────────────────────────────

function Spinner() {
  return (
    <iconify-icon
      icon="solar:spinner-linear"
      class="animate-spin text-lg"
      aria-hidden="true"
    />
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// App — auth modes: "login" | "signup" | "forgotPassword"
// ─────────────────────────────────────────────────────────────────────────────

export default function App() {
  // Temporary in-memory users registered during this browser session.
  // Cleared on refresh; never persisted.
  const [sessionUsers, setSessionUsers] = useState([]);

  const [mode, setMode] = useState('login');

  // Per-form field state
  const [loginEmail,    setLoginEmail]    = useState('');
  const [loginPassword, setLoginPassword] = useState('');

  const [signupName,     setSignupName]     = useState('');
  const [signupEmail,    setSignupEmail]    = useState('');
  const [signupPassword, setSignupPassword] = useState('');
  const [signupConfirm,  setSignupConfirm]  = useState('');

  const [forgotEmail, setForgotEmail] = useState('');

  // Error messages scoped to each form
  const [loginError,  setLoginError]  = useState('');
  const [signupError, setSignupError] = useState('');
  const [forgotError, setForgotError] = useState('');

  // Cross-form status banner (success/info after signup or forgot-password)
  const [banner, setBanner] = useState(null); // { message, tone }

  // Loading state per submit button
  const [loginLoading,  setLoginLoading]  = useState(false);
  const [signupLoading, setSignupLoading] = useState(false);
  const [forgotLoading, setForgotLoading] = useState(false);

  // Shake animation on failed login
  const [isShaking, setIsShaking] = useState(false);

  // ── Heading / subheading per mode ──────────────────────────────────────────

  const headings = {
    login:         { h: 'Welcome back',        sub: 'Sign in to the analyst dashboard' },
    signup:        { h: 'Create your account', sub: 'Create a frontend testing account with basic analyst access.' },
    forgotPassword:{ h: 'Reset your password', sub: 'Enter your email and we\'ll show the reset flow placeholder for this demo.' },
  };

  // ── Mode switcher ───────────────────────────────────────────────────────────

  function switchMode(next) {
    setMode(next);
    setBanner(null);
    setLoginError('');
    setSignupError('');
    setForgotError('');
  }

  // ── Sign In ─────────────────────────────────────────────────────────────────

  async function handleLogin(e) {
    e.preventDefault();
    setLoginError('');
    setBanner(null);

    const email    = loginEmail.trim();
    const password = loginPassword;

    if (!email || !password) {
      setLoginError('Email and password are required.');
      return;
    }
    if (!validateEmail(email)) {
      setLoginError('Enter a valid email address.');
      return;
    }

    setLoginLoading(true);
    const user = await loginUser({ email, password }, sessionUsers);
    setLoginLoading(false);

    if (!user) {
      setLoginError('Invalid email or password.');
      setLoginPassword('');
      setIsShaking(true);
      setTimeout(() => setIsShaking(false), 200);
      return;
    }

    // In a real flow replace this with token storage + redirect.
    // The backend must issue a signed session or JWT.
    window.location.href = '/';
  }

  // ── Sign Up ─────────────────────────────────────────────────────────────────

  async function handleSignup(e) {
    e.preventDefault();
    setSignupError('');
    setBanner(null);

    // Temporary frontend-only signup for demo testing.
    // Production signup must use POST /api/auth/register.
    // Backend must validate input, hash passwords, enforce RBAC, and assign a safe default role.
    // Never allow users to self-register as Admin.

    const name     = signupName.trim();
    const email    = signupEmail.trim();
    const password = signupPassword;
    const confirm  = signupConfirm;

    if (!name)                        { setSignupError('Full name is required.');                        return; }
    if (!email)                       { setSignupError('Email address is required.');                    return; }
    if (!validateEmail(email))        { setSignupError('Enter a valid email address.');                  return; }
    if (!password)                    { setSignupError('Password is required.');                         return; }
    if (password.length < 8)          { setSignupError('Password must be at least 8 characters.');       return; }
    if (password !== confirm)         { setSignupError('Passwords do not match.');                       return; }

    const allUsers = [...DEMO_USERS, ...sessionUsers];
    if (allUsers.some(u => u.email.toLowerCase() === email.toLowerCase())) {
      setSignupError('An account with this email already exists.');
      return;
    }

    setSignupLoading(true);
    await wait(400);
    setSignupLoading(false);

    // Assign lowest-privilege role — never Admin.
    // POST /api/auth/register — expected payload: { name, email, password }
    // Backend must assign the default role; frontend must never send a role field.
    setSessionUsers(prev => [...prev, { role: 'Analyst', email, password, name }]);

    // Clear signup form
    setSignupName('');
    setSignupEmail('');
    setSignupPassword('');
    setSignupConfirm('');

    switchMode('login');
    setBanner({ message: 'Account created for frontend testing. You can now sign in.', tone: 'success' });
  }

  // ── Forgot Password ─────────────────────────────────────────────────────────

  async function handleForgotPassword(e) {
    e.preventDefault();
    setForgotError('');
    setBanner(null);

    // Temporary frontend-only forgot password flow.
    // Production forgot password must use POST /api/auth/forgot-password.
    // Response must be generic to avoid account enumeration.
    // POST /api/auth/forgot-password — expected payload: { email }
    // Backend: validate email, create secure reset token, send email,
    // return generic response regardless of whether the account exists.

    const email = forgotEmail.trim();
    if (!email)                { setForgotError('Email address is required.');    return; }
    if (!validateEmail(email)) { setForgotError('Enter a valid email address.'); return; }

    setForgotLoading(true);
    await wait(400);
    setForgotLoading(false);

    // Always show generic message — never reveal whether the email exists.
    setForgotEmail('');
    setBanner({
      message: 'If an account exists for this email, password reset instructions will be sent.',
      tone: 'info',
    });
  }

  // ── Shared input className ──────────────────────────────────────────────────

  const inputCls =
    'w-full pl-10 pr-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm ' +
    'focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 ' +
    'transition-all text-slate-900 shadow-sm placeholder:text-slate-400';

  const { h, sub } = headings[mode];

  // ── Banner styles ───────────────────────────────────────────────────────────

  const bannerCls = banner
    ? banner.tone === 'success'
      ? 'flex items-start bg-emerald-50 border border-emerald-100 text-emerald-700 px-4 py-3 rounded-xl mb-5 text-sm font-medium'
      : 'flex items-start bg-indigo-50 border border-indigo-100 text-indigo-700 px-4 py-3 rounded-xl mb-5 text-sm font-medium'
    : '';

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <main className="w-full max-w-[460px] flex flex-col items-center">

      {/* Auth card */}
      <div
        className={`w-full bg-white rounded-3xl border border-slate-200 p-7 sm:p-9 shadow-[0_8px_30px_rgba(15,23,42,0.08)] relative z-10 transition-transform ${isShaking ? 'animate-shake' : ''}`}
        aria-labelledby="auth-heading"
      >
        {/* Logo */}
        <div className="flex items-center justify-center mb-7">
          <div className="w-12 h-12 bg-slate-900 rounded-2xl flex items-center justify-center mr-3 shadow-sm">
            <iconify-icon icon="solar:shield-linear" class="text-white text-xl" stroke-width="1.5" aria-hidden="true" />
          </div>
          <span className="font-semibold text-2xl tracking-tight text-slate-900">PhishGuard</span>
        </div>

        {/* Dynamic heading */}
        <div className="text-center mb-6">
          <h1 id="auth-heading" className="text-xl sm:text-2xl font-semibold tracking-tight text-slate-900 mb-1">
            {h}
          </h1>
          <p className="text-sm text-slate-500">{sub}</p>
        </div>

        {/* Cross-form banner */}
        {banner && (
          <div className={bannerCls} aria-live="polite" role="status">
            <iconify-icon
              icon={banner.tone === 'success' ? 'solar:check-circle-linear' : 'solar:info-circle-linear'}
              class="text-lg mr-2.5 shrink-0 mt-0.5"
              stroke-width="1.5"
              aria-hidden="true"
            />
            <span>{banner.message}</span>
          </div>
        )}

        {/* ═══ SIGN IN ═══════════════════════════════════════════════ */}
        {mode === 'login' && (
          <>
            <form onSubmit={handleLogin} className="space-y-4" noValidate>

              {/* Email */}
              <div>
                <label htmlFor="login-email" className="block text-xs font-medium text-slate-700 mb-1.5">
                  Email Address
                </label>
                <div className="relative">
                  <iconify-icon icon="solar:letter-linear" class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-lg pointer-events-none" aria-hidden="true" />
                  <input
                    id="login-email"
                    type="email"
                    autoComplete="email"
                    value={loginEmail}
                    onChange={e => setLoginEmail(e.target.value)}
                    placeholder="admin@phishguard.test"
                    className={inputCls}
                    aria-describedby={loginError ? 'login-error' : undefined}
                    aria-invalid={!!loginError}
                    required
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label htmlFor="login-password" className="block text-xs font-medium text-slate-700">
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => switchMode('forgotPassword')}
                    className="text-xs font-medium text-indigo-600 hover:text-indigo-700 transition-colors"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <iconify-icon icon="solar:lock-keyhole-linear" class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-lg pointer-events-none" aria-hidden="true" />
                  <input
                    id="login-password"
                    type="password"
                    autoComplete="current-password"
                    value={loginPassword}
                    onChange={e => setLoginPassword(e.target.value)}
                    placeholder="Enter your password"
                    className={inputCls}
                    aria-describedby={loginError ? 'login-error' : undefined}
                    aria-invalid={!!loginError}
                    required
                  />
                </div>
              </div>

              {/* Inline error */}
              {loginError && (
                <p id="login-error" className="flex items-center text-xs text-rose-600 font-medium" aria-live="polite">
                  <iconify-icon icon="solar:danger-circle-linear" class="mr-1.5 text-base shrink-0" aria-hidden="true" />
                  {loginError}
                </p>
              )}

              <button
                type="submit"
                disabled={loginLoading}
                className="w-full flex items-center justify-center bg-slate-900 text-white font-medium text-sm py-2.5 rounded-xl shadow-sm hover:bg-slate-800 transition-colors mt-2 h-11 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {loginLoading ? <Spinner /> : (
                  <>
                    Sign In
                    <iconify-icon icon="solar:arrow-right-linear" class="ml-2 text-base" stroke-width="1.5" aria-hidden="true" />
                  </>
                )}
              </button>
            </form>

            <p className="mt-5 text-center text-sm text-slate-500">
              Don't have an account?{' '}
              <button
                type="button"
                onClick={() => switchMode('signup')}
                className="font-medium text-indigo-600 hover:text-indigo-700 transition-colors"
              >
                Sign up
              </button>
            </p>
          </>
        )}

        {/* ═══ SIGN UP ═══════════════════════════════════════════════ */}
        {mode === 'signup' && (
          <>
            <form onSubmit={handleSignup} className="space-y-4" noValidate>

              {/* Full name */}
              <div>
                <label htmlFor="signup-name" className="block text-xs font-medium text-slate-700 mb-1.5">
                  Full Name
                </label>
                <div className="relative">
                  <iconify-icon icon="solar:user-linear" class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-lg pointer-events-none" aria-hidden="true" />
                  <input
                    id="signup-name"
                    type="text"
                    autoComplete="name"
                    value={signupName}
                    onChange={e => setSignupName(e.target.value)}
                    placeholder="Your full name"
                    className={inputCls}
                    aria-describedby={signupError ? 'signup-error' : undefined}
                    aria-invalid={!!signupError}
                    required
                  />
                </div>
              </div>

              {/* Email */}
              <div>
                <label htmlFor="signup-email" className="block text-xs font-medium text-slate-700 mb-1.5">
                  Email Address
                </label>
                <div className="relative">
                  <iconify-icon icon="solar:letter-linear" class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-lg pointer-events-none" aria-hidden="true" />
                  <input
                    id="signup-email"
                    type="email"
                    autoComplete="email"
                    value={signupEmail}
                    onChange={e => setSignupEmail(e.target.value)}
                    placeholder="you@example.com"
                    className={inputCls}
                    aria-describedby={signupError ? 'signup-error' : undefined}
                    aria-invalid={!!signupError}
                    required
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label htmlFor="signup-password" className="block text-xs font-medium text-slate-700 mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <iconify-icon icon="solar:lock-keyhole-linear" class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-lg pointer-events-none" aria-hidden="true" />
                  <input
                    id="signup-password"
                    type="password"
                    autoComplete="new-password"
                    value={signupPassword}
                    onChange={e => setSignupPassword(e.target.value)}
                    placeholder="At least 8 characters"
                    className={inputCls}
                    aria-describedby={signupError ? 'signup-error' : undefined}
                    aria-invalid={!!signupError}
                    required
                    minLength={8}
                  />
                </div>
              </div>

              {/* Confirm password */}
              <div>
                <label htmlFor="signup-confirm" className="block text-xs font-medium text-slate-700 mb-1.5">
                  Confirm Password
                </label>
                <div className="relative">
                  <iconify-icon icon="solar:lock-keyhole-linear" class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-lg pointer-events-none" aria-hidden="true" />
                  <input
                    id="signup-confirm"
                    type="password"
                    autoComplete="new-password"
                    value={signupConfirm}
                    onChange={e => setSignupConfirm(e.target.value)}
                    placeholder="Repeat your password"
                    className={inputCls}
                    aria-describedby={signupError ? 'signup-error' : undefined}
                    aria-invalid={!!signupError}
                    required
                  />
                </div>
              </div>

              {/* Inline error */}
              {signupError && (
                <p id="signup-error" className="flex items-center text-xs text-rose-600 font-medium" aria-live="polite">
                  <iconify-icon icon="solar:danger-circle-linear" class="mr-1.5 text-base shrink-0" aria-hidden="true" />
                  {signupError}
                </p>
              )}

              <button
                type="submit"
                disabled={signupLoading}
                className="w-full flex items-center justify-center bg-slate-900 text-white font-medium text-sm py-2.5 rounded-xl shadow-sm hover:bg-slate-800 transition-colors mt-2 h-11 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {signupLoading ? <Spinner /> : (
                  <>
                    Create Account
                    <iconify-icon icon="solar:arrow-right-linear" class="ml-2 text-base" stroke-width="1.5" aria-hidden="true" />
                  </>
                )}
              </button>
            </form>

            <p className="mt-5 text-center text-sm text-slate-500">
              Already have an account?{' '}
              <button
                type="button"
                onClick={() => switchMode('login')}
                className="font-medium text-indigo-600 hover:text-indigo-700 transition-colors"
              >
                Sign in
              </button>
            </p>
          </>
        )}

        {/* ═══ FORGOT PASSWORD ═══════════════════════════════════════ */}
        {mode === 'forgotPassword' && (
          <>
            <form onSubmit={handleForgotPassword} className="space-y-4" noValidate>

              {/* Email */}
              <div>
                <label htmlFor="forgot-email" className="block text-xs font-medium text-slate-700 mb-1.5">
                  Email Address
                </label>
                <div className="relative">
                  <iconify-icon icon="solar:letter-linear" class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-lg pointer-events-none" aria-hidden="true" />
                  <input
                    id="forgot-email"
                    type="email"
                    autoComplete="email"
                    value={forgotEmail}
                    onChange={e => setForgotEmail(e.target.value)}
                    placeholder="Enter your email"
                    className={inputCls}
                    aria-describedby={forgotError ? 'forgot-error' : undefined}
                    aria-invalid={!!forgotError}
                    required
                  />
                </div>
              </div>

              {/* Inline error */}
              {forgotError && (
                <p id="forgot-error" className="flex items-center text-xs text-rose-600 font-medium" aria-live="polite">
                  <iconify-icon icon="solar:danger-circle-linear" class="mr-1.5 text-base shrink-0" aria-hidden="true" />
                  {forgotError}
                </p>
              )}

              <button
                type="submit"
                disabled={forgotLoading}
                className="w-full flex items-center justify-center bg-slate-900 text-white font-medium text-sm py-2.5 rounded-xl shadow-sm hover:bg-slate-800 transition-colors mt-2 h-11 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {forgotLoading ? <Spinner /> : (
                  <>
                    Send Reset Instructions
                    <iconify-icon icon="solar:arrow-right-linear" class="ml-2 text-base" stroke-width="1.5" aria-hidden="true" />
                  </>
                )}
              </button>
            </form>

            <p className="mt-5 text-center text-sm text-slate-500">
              <button
                type="button"
                onClick={() => switchMode('login')}
                className="font-medium text-indigo-600 hover:text-indigo-700 transition-colors"
              >
                ← Back to sign in
              </button>
            </p>
          </>
        )}

        {/* Demo notice badge */}
        <div className="mt-6 p-4 bg-indigo-50/60 border border-indigo-100 rounded-xl flex items-start text-left">
          <div className="w-9 h-9 rounded-full bg-white border border-indigo-100 flex items-center justify-center text-indigo-600 shrink-0 mr-3 shadow-sm">
            <iconify-icon icon="solar:shield-check-linear" class="text-lg" stroke-width="1.5" aria-hidden="true" />
          </div>
          <div>
            <p className="text-xs text-indigo-700 font-semibold">Demo access is enabled for frontend testing only.</p>
            <p className="text-[11px] text-indigo-600/70 mt-1 leading-relaxed">
              Production authentication will be connected through the backend API.
            </p>
          </div>
        </div>
      </div>

      {/* Demo credentials card */}
      <div className="w-full mt-5 bg-white border border-slate-200/70 rounded-xl p-5 shadow-sm text-sm">
        <h3 className="font-medium text-slate-900 mb-3 flex items-center">
          <iconify-icon icon="solar:info-circle-linear" class="text-indigo-500 mr-2 text-lg" stroke-width="1.5" aria-hidden="true" />
          Demo Credentials
        </h3>
        <div className="space-y-2">
          <div className="flex justify-between items-center bg-slate-50 px-3 py-2 rounded-lg border border-slate-100">
            <span className="text-slate-500 font-medium text-xs">Admin</span>
            <span className="font-mono text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-sm text-xs">
              admin@phishguard.test / admin123
            </span>
          </div>
          <div className="flex justify-between items-center bg-slate-50 px-3 py-2 rounded-lg border border-slate-100">
            <span className="text-slate-500 font-medium text-xs">Analyst</span>
            <span className="font-mono text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-sm text-xs">
              analyst@phishguard.test / analyst123
            </span>
          </div>
        </div>
      </div>

      {/* Security disclaimer */}
      <p className="mt-6 text-xs text-slate-400 text-center leading-relaxed max-w-[340px]">
        This demo uses frontend-only auth. Production requires a backend with hashed passwords,
        signed sessions or tokens, and server-enforced RBAC. Signup always assigns the lowest-privilege role.
      </p>
    </main>
  );
}
