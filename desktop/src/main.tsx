import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { startRemoteDiagnostics, captureUiError } from "./services/telemetry/sentryService";

const stopDiagnostics = startRemoteDiagnostics();
if (import.meta.hot) import.meta.hot.dispose(stopDiagnostics);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement, { onUncaughtError: captureUiError, onCaughtError: captureUiError }).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
