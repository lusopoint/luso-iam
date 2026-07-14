import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { ThemeProvider } from "@lusopoint/luso-ui";
import App from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (!root) {
  throw new Error("Missing #root element in index.html");
}

createRoot(root).render(
  <StrictMode>
    <ThemeProvider defaultColorTheme="sapphire" storageKey="iam">
      <BrowserRouter basename="/admin">
        <App />
      </BrowserRouter>
    </ThemeProvider>
  </StrictMode>,
);
