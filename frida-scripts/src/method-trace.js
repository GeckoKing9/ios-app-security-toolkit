/*
 * method-trace.js — live-trace every call to methods matching a keyword, with args.
 * Great for "what does this app do when I tap X" — watch the calls fly by.
 * Usage: frida -H <ip:port> -n <AppName> -l method-trace.js
 *        then in REPL:  trace('login')   or   trace('purchase')
 */
import ObjC from 'frida-objc-bridge';   // Frida 17: bridge is no longer a global
globalThis.ObjC = ObjC;

function trace(keyword) {
  keyword = (keyword || '').toLowerCase();
  let hooked = 0;
  for (const clsName of Object.keys(ObjC.classes)) {
    if (/^(NS|UI|CA|CF|_)/.test(clsName)) continue;
    const cls = ObjC.classes[clsName];
    for (const m of cls.$ownMethods) {
      if (m.toLowerCase().indexOf(keyword) === -1) continue;
      try {
        Interceptor.attach(cls[m].implementation, {
          onEnter() { console.log('-> [' + clsName + ' ' + m + ']'); },
          onLeave(ret) { /* keep output readable; ret available if needed */ }
        });
        hooked++;
      } catch (e) {}
    }
  }
  console.log('[+] Hooked ' + hooked + ' methods matching "' + keyword + '". Interact with the app now.');
}
globalThis.trace = trace;   // expose to the interactive REPL
console.log('[+] method-trace ready. Call  trace("<keyword>")  in the REPL.');
