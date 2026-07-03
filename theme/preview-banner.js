// Inserts a "Preview edition" banner at the top of every page's content.
// Loaded via `additional-js` in book.toml so it appears in both `mdbook build`
// and `mdbook serve`. Each chapter is a full page load, so this runs per page.
(function () {
  function addBanner() {
    var main = document.querySelector('main');
    if (!main || document.getElementById('preview-banner')) return;
    var banner = document.createElement('div');
    banner.id = 'preview-banner';
    banner.setAttribute('role', 'note');
    banner.innerHTML =
      '<strong>Preview edition.</strong> This book is a work in progress: ' +
      'content may change and may still contain errors. ' +
      '<a href="https://github.com/MaliParag/windows-trust-chain/issues">Report an issue</a>.';
    main.insertBefore(banner, main.firstChild);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addBanner);
  } else {
    addBanner();
  }
})();
