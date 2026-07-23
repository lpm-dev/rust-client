import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles/global.css';
import { App } from './App';
import { createHttpDashboardApi } from './api/httpApi';

const api = createHttpDashboardApi();

const container = document.getElementById('root');
if (!container) throw new Error('#root is missing from index.html');

createRoot(container).render(
  <StrictMode>
    <App api={api} />
  </StrictMode>,
);
