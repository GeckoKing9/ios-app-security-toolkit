/*
 * spoof-ios-version.js — make an app believe it's running on iOS 17.0.
 * Defeats SOFT version gates ("please update, requires iOS 17"). Does NOT add
 * real iOS 17 APIs — apps that genuinely use iOS 17 frameworks still crash.
 * Compiled with the ObjC bridge (Frida 17). Load via: ios spoof <app>
 */
import ObjC from 'frida-objc-bridge';

const FAKE = '17.0';

// 1) UIDevice.systemVersion -> "17.0"  (the most common check)
try {
  const m = ObjC.classes.UIDevice['- systemVersion'];
  Interceptor.attach(m.implementation, {
    onLeave(ret) {
      ret.replace(ObjC.classes.NSString.stringWithString_(FAKE));
    }
  });
  console.log('[+] UIDevice.systemVersion -> ' + FAKE);
} catch (e) { console.log('[-] UIDevice hook failed: ' + e); }

// 2) NSProcessInfo.isOperatingSystemAtLeastVersion: -> always YES
try {
  const m = ObjC.classes.NSProcessInfo['- isOperatingSystemAtLeastVersion:'];
  Interceptor.attach(m.implementation, {
    onLeave(ret) { ret.replace(ptr(1)); }   // force "yes, at least that version"
  });
  console.log('[+] NSProcessInfo.isOperatingSystemAtLeastVersion: -> always YES');
} catch (e) { console.log('[-] NSProcessInfo hook failed: ' + e); }

console.log('[+] iOS version spoof active (soft gates only).');
