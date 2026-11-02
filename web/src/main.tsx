import '@cloudscape-design/global-styles/index.css';
import './styles.css';
import { applyMode, Mode } from '@cloudscape-design/global-styles';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './app/App';
import { I18nProvider } from './i18n';

// Follow the operating system light/dark preference.
const dark = window.matchMedia('(prefers-color-scheme: dark)');
const syncMode = () => applyMode(dark.matches ? Mode.Dark : Mode.Light);
syncMode();
dark.addEventListener('change', syncMode);

const root = document.getElementById('root');
if (!root) throw new Error('root element missing');
createRoot(root).render(
  <StrictMode>
    <I18nProvider>
      <App />
    </I18nProvider>
  </StrictMode>,
);
