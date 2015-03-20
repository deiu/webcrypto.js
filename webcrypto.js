(function(root) {
  if( typeof $webCrypto === 'undefined' ) {
      var $webCrypto = {};
  } else {
    return $webCrypto;
    throw "Internal error: WebCrypto libray has already been loaded: $webCrypto already exists";
  }

  var crypto = window.crypto || window.msCrypto;
  if (!crypto.subtle) {
    return;
    throw "WebCrypto API support missing from browser.";
  }

  $webCrypto.signAlgorithm = {
    name: "RSASSA-PKCS1-v1_5",
    hash: {
      name: "SHA-256"
    }
  }

  $webCrypto.generateRSAKey = function() {
    var alg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: {name: "SHA-256"},
      modulusLength: 2048,
      extractable: true,
      publicExponent: new Uint8Array([1, 0, 1])
    };
    
    return new Promise(function(resolve) {
      var genkey = crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
      genkey.then(function (pair) { 
        resolve(pair);
      });
    });
  }

  $webCrypto.arrayBufferToBase64String = function(arrayBuffer) {
    var byteArray = new Uint8Array(arrayBuffer)
    var byteString = '';
    for (var i=0; i<byteArray.byteLength; i++) {
      byteString += String.fromCharCode(byteArray[i]);
    }
    return btoa(byteString);
  };

  $webCrypto.base64StringToArrayBuffer = function(b64str) {
    var byteStr = atob(b64str);
    var bytes = new Uint8Array(byteStr.length);
    for (var i = 0; i < byteStr.length; i++) {
      bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
  };

  $webCrypto.textToArrayBuffer = function(str) {
    var buf = unescape(encodeURIComponent(str)); // 2 bytes for each char
    var bufView = new Uint8Array(buf.length);
    for (var i=0; i < buf.length; i++) {
      bufView[i] = buf.charCodeAt(i);
    }
    return bufView;
  };

  $webCrypto.arraySignatureToBase64 = function(arr) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(arr)));
  };

  $webCrypto.convertBinaryToPem = function(binaryData, label) {
    var base64Cert = $webCrypto.arrayBufferToBase64String(binaryData);
    var pemCert = "-----BEGIN " + label + "-----\r\n";
    var nextIndex = 0;
    var lineLength;
    while (nextIndex < base64Cert.length) {
      if (nextIndex + 64 <= base64Cert.length) {
        pemCert += base64Cert.substr(nextIndex, 64) + "\r\n";
      } else {
        pemCert += base64Cert.substr(nextIndex) + "\r\n";
      }
      nextIndex += 64;
    }
    pemCert += "-----END " + label + "-----\r\n";
    return pemCert;
  };

  $webCrypto.convertPemToBinary = function(pem) {
    var lines = pem.split('\n');
    var encoded = '';
    for(var i = 0;i < lines.length;i++){
      if (lines[i].trim().length > 0 &&
          lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 && 
          lines[i].indexOf('-BEGIN RSA PUBLIC KEY-') < 0 &&
          lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
          lines[i].indexOf('-END RSA PUBLIC KEY-') < 0) {
        encoded += lines[i].trim();
      }
    }
    return $webCrypto.base64StringToArrayBuffer(encoded);
  };

  $webCrypto.importPublicKey = function(pemKey) {
    return new Promise(function(resolve) {
      var importer = crypto.subtle.importKey("spki", $webCrypto.convertPemToBinary(pemKey), $webCrypto.signAlgorithm, true, ["verify"]);
      importer.then(function(key) { 
        resolve(key);
      });
    });
  };

  $webCrypto.importPrivateKey = function(pemKey) {
    return new Promise(function(resolve) {
      var importer = crypto.subtle.importKey("pkcs8", $webCrypto.convertPemToBinary(pemKey), $webCrypto.signAlgorithm, true, ["sign"]);
      importer.then(function(key) { 
        resolve(key);
      });
    });
  };

  $webCrypto.exportPublicKey = function(keys) {
    return new Promise(function(resolve) {
      window.crypto.subtle.exportKey('spki', keys.publicKey).
      then(function(spki) {
        resolve($webCrypto.convertBinaryToPem(spki, "RSA PUBLIC KEY"));
      });
    });
  };

  $webCrypto.exportPrivateKey = function(keys) {
    return new Promise(function(resolve) {
      var expK = window.crypto.subtle.exportKey('pkcs8', keys.privateKey);
      expK.then(function(pkcs8) {
        resolve($webCrypto.convertBinaryToPem(pkcs8, "RSA PRIVATE KEY"));
      });
    });
  };

  $webCrypto.exportPemKeys = function(keys) {
    return new Promise(function(resolve) {
      $webCrypto.exportPublicKey(keys).then(function(pubKey) {
        $webCrypto.exportPrivateKey(keys).then(function(privKey) {
          resolve({publicKey: pubKey, privateKey: privKey});
        });
      });
    });
  };

  $webCrypto.signData = function(key, data) {
    var buffer = $webCrypto.textToArrayBuffer(data);
    console.log();
    return window.crypto.subtle.sign($webCrypto.signAlgorithm, key, buffer);
  };

  $webCrypto.verifySig = function(pub, sig, data) {
    data = $webCrypto.textToArrayBuffer(data);
    return crypto.subtle.verify($webCrypto.signAlgorithm, pub, sig, data);
  };

  // Handle node, amd, and global systems
  if (typeof exports !== 'undefined') {
    if (typeof module !== 'undefined' && module.exports) {
      exports = module.exports = $webCrypto;
    }
    exports.$webCrypto = $webCrypto;
  } else {
    if (typeof define === 'function' && define.amd) {
      define([], function() {
        return $webCrypto;
      });
    }

    // Leak a global regardless of module system
    root['$webCrypto'] = $webCrypto;
  }
})(this);
