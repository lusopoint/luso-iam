import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import App from "./App";
import "./styles.css";

// The Go server mounts the SPA under /admin/, and Vite is configured with
// `base: "/admin/"`. React Router needs the same prefix so that <Link to="/users">
// generates /admin/users, not just /users.
const root = document.getElementById("root");
if (!root) {
  throw new Error("Missing #root element in index.html");
}

createRoot(root).render(
  <StrictMode>
    <BrowserRouter basename="/admin">
      <App />
    </BrowserRouter>
  </StrictMode>,
);
