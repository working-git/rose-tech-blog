// highlight-init.js
// Load and initialize highlight.js

document.addEventListener('DOMContentLoaded', (event) => {
  if (window.hljs) {
    document.querySelectorAll('pre code').forEach((block) => {
      window.hljs.highlightElement(block);
    });
  }
});
