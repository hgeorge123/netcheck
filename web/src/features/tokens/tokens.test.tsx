import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderI18n } from '../../test/render';
import type { ApiToken } from '../../types/api';
import { TokensPage } from './TokensPage';

const token: ApiToken = { id: 't1', name: 'payments pipeline', prefix: 'nck_ab12', owner: 'bob', createdAt: '2026-11-01T10:00:00Z', expiresAt: '2099-01-01T00:00:00Z' };

describe('TokensPage', () => {
  it('creates a token and shows its secret once, with a CLI example', async () => {
    const list = vi.fn().mockResolvedValueOnce({ items: [] }).mockResolvedValue({ items: [token] });
    const create = vi.fn().mockResolvedValue({ token: 'nck_secret-value', item: token });
    renderI18n(<TokensPage scope="mine" list={list} create={create} revoke={vi.fn()} notify={vi.fn()} />);
    expect(await screen.findByText('No tokens')).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole('button', { name: 'Create token' })[0]!);
    await userEvent.type(screen.getByRole('textbox', { name: 'Name' }), 'payments pipeline');
    await userEvent.click(screen.getAllByRole('button', { name: 'Create token' }).at(-1)!);
    await waitFor(() => expect(create).toHaveBeenCalledWith('payments pipeline', 90));
    expect(await screen.findByTestId('token-secret')).toHaveTextContent('nck_secret-value');
    expect(screen.getByText(/netcheck-cli run -n <namespace>/)).toBeInTheDocument();
    expect(await screen.findByText('nck_ab12…')).toBeInTheDocument();
  });

  it('lets administrators see owners and revoke, without creating', async () => {
    const revoke = vi.fn().mockResolvedValue(undefined);
    const notify = vi.fn();
    renderI18n(<TokensPage scope="all" list={vi.fn().mockResolvedValue({ items: [token] })} revoke={revoke} notify={notify} />);
    expect(await screen.findByText('bob')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create token' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('radio', { name: 'payments pipeline' }));
    await userEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    await userEvent.click(screen.getAllByRole('button', { name: 'Revoke' }).at(-1)!);
    await waitFor(() => expect(revoke).toHaveBeenCalledWith('t1'));
    expect(notify).toHaveBeenCalledWith('success', 'Token "payments pipeline" revoked.');
  });
});
