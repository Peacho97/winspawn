// spawn_hidden.cjs - hidden-by-default child processes for Node on Windows.
//
// Node's child_process will happily pop a console window: `detached: true`
// gives the child its own console, and exec()/execSync() route through
// cmd.exe. Both flash. These wrappers force `windowsHide: true` and strip
// `detached`, and prefer execFile (no shell) over exec.
//
//   const { spawnHidden, execFileHidden } = require('./node/spawn_hidden.cjs');
//   const child = spawnHidden('node', ['server.js'], { cwd: root });
//
// Note: `detached` is deleted from the options, never honoured. Child processes
// that are GUI programs still show their own windows.
//
// Escape hatch (audited by `python -m winspawn --audit`): put
// `// spawn-hidden-ok: <reason>` on the offending line.

const child_process = require('child_process');

/** Normalize options: windowsHide always on, detached never. */
function hiddenOpts(opts) {
  const out = Object.assign({}, opts || {});
  delete out.detached;
  out.windowsHide = true;
  return out;
}

/** child_process.spawn with a hidden window (windowsHide: true). */
function spawnHidden(cmd, args, opts) {
  return child_process.spawn(cmd, args || [], hiddenOpts(opts));
}

/** child_process.execFile with a hidden window (windowsHide: true) (no shell). */
function execFileHidden(cmd, args, opts, callback) {
  if (typeof opts === 'function') {
    callback = opts;
    opts = undefined;
  }
  if (callback) {
    return child_process.execFile(cmd, args || [], hiddenOpts(opts), callback);
  }
  return child_process.execFile(cmd, args || [], hiddenOpts(opts));
}

module.exports = { spawnHidden, execFileHidden, hiddenOpts };
