Third-party browser code used by the console relay. Served locally; no CDN.

novnc-rfb-1.6.0.min.js
  noVNC 1.6.0, npm package @novnc/novnc (lib/ folder), bundled into one script with
  esbuild 0.24.2 (--bundle --minify --format=iife --global-name=noVNC). window.noVNC.default
  is the RFB class. One change before bundling: lib/util/browser.js used a top-level await
  for H.264 detection, replaced by a promise so the CommonJS build can be bundled.
  License: noVNC core MPL-2.0 (LICENSE-noVNC.txt, LICENSE-noVNC-MPL-2.0.txt);
  bundled pako: MIT. https://github.com/novnc/noVNC

xterm-5.5.0.js, xterm-5.5.0.css
  xterm.js 5.5.0, npm package @xterm/xterm (lib/xterm.js, css/xterm.css). MIT (LICENSE-xterm.txt).
  https://github.com/xtermjs/xterm.js

xterm-addon-fit-0.10.0.js
  @xterm/addon-fit 0.10.0 (lib/addon-fit.js). MIT, same project and license.
