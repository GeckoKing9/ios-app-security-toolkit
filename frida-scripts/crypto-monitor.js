/*
 * crypto-monitor.js — trace CommonCrypto usage in a live iOS app.
 * Reveals encryption keys, IVs, and plaintext as they pass through the app.
 * Usage: frida -H <ip:port> -f <bundleid> -l crypto-monitor.js
 */
const CCCrypt = Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt');
if (CCCrypt) {
  Interceptor.attach(CCCrypt, {
    onEnter(args) {
      // CCCrypt(op, alg, options, key, keyLen, iv, dataIn, dataInLen, ...)
      const keyLen = args[4].toInt32();
      const dataLen = args[7].toInt32();
      console.log('\n[CCCrypt] op=' + args[0].toInt32() + ' alg=' + args[1].toInt32());
      console.log('  key(' + keyLen + '): ' + Memory.readByteArray(args[3], Math.min(keyLen, 64)));
      console.log('  iv: ' + Memory.readByteArray(args[5], 16));
      console.log('  dataIn(' + dataLen + '): ' + Memory.readByteArray(args[6], Math.min(dataLen, 128)));
    }
  });
  console.log('[+] Hooked CCCrypt — crypto ops will print here.');
} else {
  console.log('[-] CCCrypt not found in this process.');
}

// Also trace hashing (often used for signing/integrity checks)
['CC_MD5', 'CC_SHA1', 'CC_SHA256'].forEach(function (fn) {
  const p = Module.findExportByName('libcommonCrypto.dylib', fn);
  if (p) Interceptor.attach(p, {
    onEnter(args) {
      const len = args[1].toInt32();
      console.log('[' + fn + '] input(' + len + '): ' + Memory.readByteArray(args[0], Math.min(len, 128)));
    }
  });
});
