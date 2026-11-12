import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'

import App from './App'
import { lockSession, useSessionStore } from './session/store'

beforeEach(() => {
  lockSession()
})

describe('App', () => {
  it('shows the sign-in screen and the honest footer', () => {
    render(<App />)

    expect(screen.getByRole('heading', { name: 'Parley' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
    expect(
      screen.getByText('Experimental, not audited. See THREAT_MODEL.'),
    ).toBeInTheDocument()
  })

  it('switches between sign in and registration', () => {
    render(<App />)

    fireEvent.click(screen.getByRole('button', { name: 'Create an account' }))

    expect(
      screen.getByRole('heading', { name: 'Create account' }),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Back to sign in' }))

    expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('shows the signed-in panel for an unlocked session', () => {
    useSessionStore.getState().setUnlocked('alice', 'public-key')

    render(<App />)

    expect(
      screen.getByRole('heading', { name: 'Signed in' }),
    ).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
  })
})
