// Minimal end-to-end proof that the Frida-17 ObjC bridge works on-device.
import ObjC from 'frida-objc-bridge';

const dev = ObjC.classes.UIDevice.currentDevice();
console.log('BRIDGE_OK'
  + ' MODEL=' + dev.model()
  + ' VERSION=' + dev.systemVersion()
  + ' NAME=' + dev.name());
