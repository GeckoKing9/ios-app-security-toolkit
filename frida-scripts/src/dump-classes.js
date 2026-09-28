/*
 * dump-classes.js — enumerate an app's own Objective-C classes + methods at runtime.
 * The Frida-era replacement for class-dump (works on encrypted App Store binaries,
 * because the app is already decrypted in memory once it's running).
 * Usage: frida -H <ip:port> -n <AppName> -l dump-classes.js
 *        then in the REPL:  dumpApp('myapp')    // filter substring, case-insensitive
 */
import ObjC from 'frida-objc-bridge';   // Frida 17: bridge is no longer a global
globalThis.ObjC = ObjC;

function dumpApp(filter) {
  filter = (filter || '').toLowerCase();
  const out = [];
  for (const name of Object.keys(ObjC.classes)) {
    if (filter && name.toLowerCase().indexOf(filter) === -1) continue;
    // skip Apple framework classes unless explicitly asked
    if (!filter && /^(NS|UI|CA|CF|_)/.test(name)) continue;
    const cls = ObjC.classes[name];
    const methods = cls.$ownMethods;
    out.push(name + '  (' + methods.length + ' methods)');
    for (const m of methods) out.push('    ' + m);
  }
  console.log(out.join('\n'));
  console.log('\n[+] ' + out.length + ' lines. Narrow with dumpApp("keyword").');
}
globalThis.dumpApp = dumpApp;   // expose to the interactive REPL
console.log('[+] dump-classes ready. Call  dumpApp("<keyword>")  in the REPL.');
