import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../services/api';
import { renderI18n } from '../../test/render';
import { ChangePasswordPage } from './ChangePasswordPage';
import { LoginPage } from './LoginPage';
import { generatePassword } from './password';

describe('LoginPage', () => {
  it('is in English by default and logs in', async () => {
    const login = vi.fn().mockResolvedValue({ mustChangePassword: false });
    const onLoggedIn = vi.fn();
    renderI18n(<LoginPage login={login} onLoggedIn={onLoggedIn} />);
    expect(screen.getByRole('img', { name: 'NetCheck' })).toHaveAttribute('src', '/brand/netcheck-logo.png');
    await userEvent.type(screen.getByLabelText('Username'), ' alice ');
    await userEvent.type(screen.getByLabelText('Password'), 'secret-password-1');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(onLoggedIn).toHaveBeenCalled());
    expect(login).toHaveBeenCalledWith('alice', 'secret-password-1');
    expect((screen.getByLabelText('Password') as HTMLInputElement).type).toBe('password');
  });

  it('translates the server error by code', async () => {
    const login = vi.fn().mockRejectedValue(new ApiError(401, 'invalid_credentials', 'invalid username or password'));
    renderI18n(<LoginPage login={login} onLoggedIn={vi.fn()} />, 'es');
    await userEvent.type(screen.getByLabelText('Usuario'), 'alice');
    await userEvent.type(screen.getByLabelText('Contraseña'), 'x');
    await userEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }));
    expect((await screen.findAllByText(/Usuario o contraseña incorrectos/)).length).toBeGreaterThan(0);
  });

  it('validates empty fields locally', async () => {
    const login = vi.fn();
    renderI18n(<LoginPage login={login} onLoggedIn={vi.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect((await screen.findAllByText('Enter your username and password.')).length).toBeGreaterThan(0);
    expect(login).not.toHaveBeenCalled();
  });
});

describe('ChangePasswordPage', () => {
  const fill = async (cur: string, next: string, confirm: string) => {
    await userEvent.type(screen.getByLabelText('Current password'), cur);
    await userEvent.type(screen.getByLabelText('New password'), next);
    await userEvent.type(screen.getByLabelText('Confirm new password'), confirm);
    await userEvent.click(screen.getByRole('button', { name: 'Save password' }));
  };

  it('forces the change and validates locally', async () => {
    const change = vi.fn();
    renderI18n(<ChangePasswordPage forced change={change} onChanged={vi.fn()} />);
    expect(screen.getByText('Change your password')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel' })).toBeNull();
    await fill('temporary-pass', 'short', 'short');
    expect(await screen.findByText('At least 12 characters.')).toBeInTheDocument();
    expect(change).not.toHaveBeenCalled();
  });

  it('rejects a mismatched confirmation', async () => {
    const change = vi.fn();
    renderI18n(<ChangePasswordPage forced change={change} onChanged={vi.fn()} />);
    await fill('temporary-pass', 'a-long-new-password', 'a-different-password');
    expect(await screen.findByText('The passwords do not match.')).toBeInTheDocument();
    expect(change).not.toHaveBeenCalled();
  });

  it('maps a wrong current password to its field', async () => {
    const change = vi
      .fn()
      .mockRejectedValue(
        new ApiError(400, 'validation_failed', 'the current password is not correct', [
          { field: 'currentPassword', code: 'current_password_wrong', message: 'the current password is not correct' },
        ]),
      );
    renderI18n(<ChangePasswordPage forced={false} change={change} onChanged={vi.fn()} onCancel={vi.fn()} />);
    await fill('wrong-current', 'a-long-new-password', 'a-long-new-password');
    expect(await screen.findByText('The current password is not correct.')).toBeInTheDocument();
  });

  it('submits a valid change', async () => {
    const change = vi.fn().mockResolvedValue(undefined);
    const onChanged = vi.fn();
    renderI18n(<ChangePasswordPage forced change={change} onChanged={onChanged} />);
    await fill('temporary-pass', 'a-long-new-password', 'a-long-new-password');
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    expect(change).toHaveBeenCalledWith('temporary-pass', 'a-long-new-password');
  });
});

it('generates strong temporary passwords', () => {
  const a = generatePassword();
  expect(a).toHaveLength(20);
  expect(a).toMatch(/^[a-zA-Z2-9]+$/);
  expect(generatePassword()).not.toBe(a);
});

describe('LoginPage single sign-on', () => {
  it('offers the SSO button next to the local form when it is enabled', async () => {
    const providers = vi.fn().mockResolvedValue({ oidc: { enabled: true, name: 'GitHub' } });
    renderI18n(<LoginPage login={vi.fn()} onLoggedIn={vi.fn()} providers={providers} />);
    const sso = await screen.findByRole('link', { name: 'Sign in with GitHub' });
    expect(sso).toHaveAttribute('href', '/api/v1/auth/oidc/start');
    expect(screen.getByLabelText('Username')).toBeInTheDocument(); // local accounts keep working
  });

  it('shows only the local form when SSO is disabled or unreachable', async () => {
    const providers = vi.fn().mockRejectedValue(new Error('offline'));
    renderI18n(<LoginPage login={vi.fn()} onLoggedIn={vi.fn()} providers={providers} />);
    await waitFor(() => expect(providers).toHaveBeenCalled());
    expect(screen.queryByRole('link', { name: /Sign in with/ })).not.toBeInTheDocument();
  });
});
