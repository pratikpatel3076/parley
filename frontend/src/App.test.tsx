import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import App from './App'

describe('App', () => {
  it('renders the scaffold heading and status', () => {
    render(<App />)

    expect(screen.getByRole('heading', { name: 'Parley' })).toBeInTheDocument()
    expect(screen.getByText(/not implemented yet/i)).toBeInTheDocument()
  })
})
