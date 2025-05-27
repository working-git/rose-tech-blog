// highlight-bash-args.js
// Extends highlight.js bash to highlight arguments (e.g. -l, --help)
(function() {
  if (!window.hljs) return;
  window.hljs.registerLanguage('bash-args', function(hljs) {
    var ARGUMENT = {
      className: 'hljs-arg',
      // Match - and -- arguments at start or after whitespace
      begin: /(^|\s)(-{1,2}[\w-]+)/
    };
    var BASH = window.hljs.getLanguage('bash');
    var newBash = Object.assign({}, BASH);
    newBash.contains = (BASH.contains || []).concat([ARGUMENT]);
    return newBash;
  });
})();

document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('pre code.language-bash, pre code.language-bash-args').forEach(function(block) {
    window.hljs.highlightElement(block);
    // Post-process: wrap - and -- arguments in <span class="hljs-arg">
    block.innerHTML = block.innerHTML.replace(/(\s|^)(-{1,2}[\w-]+)/g, function(match, p1, p2) {
      return p1 + '<span class="hljs-arg">' + p2 + '</span>';
    });
    // Post-process: highlight the first non-builtin command on each line
    const lines = block.innerHTML.split(/\n/);
    for (let i = 0; i < lines.length; i++) {
      let line = lines[i];
      // Use a temporary div to parse HTML
      let tempDiv = document.createElement('div');
      tempDiv.innerHTML = line;
      let found = false;
      function walk(node) {
        if (found) return;
        if (node.nodeType === Node.TEXT_NODE) {
          // Find the first word (command) in the text node
          let match = node.textContent.match(/(^|\s)([a-zA-Z0-9_\-\.\/]+)/);
          if (match) {
            // Only wrap if not empty and not just whitespace
            let before = match.index;
            let after = before + match[0].length;
            let text = node.textContent;
            let newNode = document.createElement('span');
            newNode.className = 'hljs-command';
            newNode.textContent = match[2];
            // Replace the matched command with the span
            let frag = document.createDocumentFragment();
            if (before > 0) frag.appendChild(document.createTextNode(text.slice(0, before)));
            frag.appendChild(newNode);
            frag.appendChild(document.createTextNode(text.slice(after)));
            node.parentNode.replaceChild(frag, node);
            found = true;
          }
        } else if (node.nodeType === Node.ELEMENT_NODE) {
          // Skip builtins, args, variables
          if (node.classList.contains('hljs-built_in') || node.classList.contains('hljs-arg') || node.classList.contains('hljs-variable')) return;
          for (let child of Array.from(node.childNodes)) {
            walk(child);
          }
        }
      }
      for (let child of Array.from(tempDiv.childNodes)) {
        walk(child);
      }
      lines[i] = tempDiv.innerHTML;
    }
    block.innerHTML = lines.join('\n');
  });
  console.log('Custom bash argument and command post-processing applied');
});
