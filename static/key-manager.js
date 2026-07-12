window.KeyManager = (function() {
  const PBKDF2_ITERATIONS = 600000;
  const SALT_KEY = 'key_salt';
  const ENC_RSA_KEY = 'enc_rsa_key';
  const ENC_PQC_KEY = 'enc_pqc_key';
  const ENC_DATA_KEY = 'enc_data_key';
  const WORKER_URL = '/static/key-worker.js';

  let worker = null;
  let workerPort = null;

  function connectWorker() {
    if (workerPort) return workerPort;
    try {
      worker = new SharedWorker(WORKER_URL);
      workerPort = worker.port;
      workerPort.start();
      return workerPort;
    } catch (e) {
      console.error('Failed to connect SharedWorker', e);
      return null;
    }
  }

  function postToWorker(type, data = {}) {
    return new Promise((resolve, reject) => {
      const port = connectWorker();
      if (!port) {
        reject(new Error('SharedWorker not available'));
        return;
      }
      const messageId = Date.now().toString(36) + Math.random().toString(36).substr(2);
      const handler = (event) => {
        if (event.data.messageId === messageId) {
          port.removeEventListener('message', handler);
          resolve(event.data);
        }
      };
      port.addEventListener('message', handler);
      port.start();
      port.postMessage({ ...data, type, messageId });
    });
  }

  async function getStoredKey() {
    try {
      const res = await postToWorker('get-key');
      return res.key;
    } catch (e) {
      return null;
    }
  }

  async function setWorkerKey(key) {
    await postToWorker('set-key', { key: key });
  }

  async function clearWorkerKey() {
    await postToWorker('clear-key');
  }

  async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      passwordKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  function base64ToBuffer(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function bufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  async function encryptWithKey(plaintext, cryptoKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      enc.encode(plaintext)
    );
    return {
      iv: bufferToBase64(iv.buffer),
      ciphertext: bufferToBase64(ciphertext)
    };
  }

  async function decryptWithKey(ivB64, ciphertextB64, cryptoKey) {
    const iv = base64ToBuffer(ivB64);
    const ciphertext = base64ToBuffer(ciphertextB64);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      ciphertext
    );
    const dec = new TextDecoder();
    return dec.decode(decrypted);
  }

return {
    hasStoredKeys: function() {
        return !!localStorage.getItem(ENC_RSA_KEY) && !!localStorage.getItem(ENC_PQC_KEY);
    },

    isWorkerReady: async function() {
        const key = await getStoredKey();
        return !!key;
    },

    init: async function() {
        const derivedKeyBase64 = await getStoredKey();
        if (!derivedKeyBase64) {
            return null;
        }

        const encRsa = localStorage.getItem(ENC_RSA_KEY);
        const encPqc = localStorage.getItem(ENC_PQC_KEY);
        const encData = localStorage.getItem(ENC_DATA_KEY);
        const saltB64 = localStorage.getItem(SALT_KEY);

        if (!encRsa || !encPqc || !saltB64) {
            return null;
        }

        const derivedKeyBytes = base64ToBuffer(derivedKeyBase64);
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            derivedKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        try {
            const encRsaObj = JSON.parse(encRsa);
            const encPqcObj = JSON.parse(encPqc);

            const rsaKey = await decryptWithKey(encRsaObj.iv, encRsaObj.ciphertext, cryptoKey);
            const pqcKey = await decryptWithKey(encPqcObj.iv, encPqcObj.ciphertext, cryptoKey);

            let dataKey = null;
            if (encData) {
                const encDataObj = JSON.parse(encData);
                dataKey = await decryptWithKey(encDataObj.iv, encDataObj.ciphertext, cryptoKey);
            }

            return { rsaKey, pqcKey, dataKey };
        } catch (e) {
            console.error('Decryption failed', e);
            return null;
        }
    },

    setup: async function(rsaKey, pqcKey, password) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        localStorage.setItem(SALT_KEY, bufferToBase64(salt.buffer));

        const cryptoKey = await deriveKey(password, salt);

        const rawKey = await crypto.subtle.exportKey('raw', cryptoKey);
        const rawKeyB64 = bufferToBase64(rawKey);

        const encRsa = await encryptWithKey(rsaKey, cryptoKey);
        const encPqc = await encryptWithKey(pqcKey, cryptoKey);

        localStorage.setItem(ENC_RSA_KEY, JSON.stringify(encRsa));
        localStorage.setItem(ENC_PQC_KEY, JSON.stringify(encPqc));

        await setWorkerKey(rawKeyB64);
    },

    unlock: async function(password) {
        const saltB64 = localStorage.getItem(SALT_KEY);
        if (!saltB64) return null;

        const encRsa = localStorage.getItem(ENC_RSA_KEY);
        const encPqc = localStorage.getItem(ENC_PQC_KEY);
        const encData = localStorage.getItem(ENC_DATA_KEY);

        if (!encRsa || !encPqc) return null;

        const salt = base64ToBuffer(saltB64);
        const cryptoKey = await deriveKey(password, salt);

        try {
            const encRsaObj = JSON.parse(encRsa);
            const encPqcObj = JSON.parse(encPqc);

            const rsaKey = await decryptWithKey(encRsaObj.iv, encRsaObj.ciphertext, cryptoKey);
            const pqcKey = await decryptWithKey(encPqcObj.iv, encPqcObj.ciphertext, cryptoKey);

            let dataKey = null;
            if (encData) {
                const encDataObj = JSON.parse(encData);
                dataKey = await decryptWithKey(encDataObj.iv, encDataObj.ciphertext, cryptoKey);
            }

            const rawKey = await crypto.subtle.exportKey('raw', cryptoKey);
            const rawKeyB64 = bufferToBase64(rawKey);
            await setWorkerKey(rawKeyB64);

            return { rsaKey, pqcKey, dataKey };
        } catch (e) {
            return null;
        }
    },

    storeDataKey: async function(dataKeyStr) {
        const derivedKeyBase64 = await getStoredKey();
        if (!derivedKeyBase64) {
            throw new Error('Worker key not available');
        }

        const derivedKeyBytes = base64ToBuffer(derivedKeyBase64);
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            derivedKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );

        const encData = await encryptWithKey(dataKeyStr, cryptoKey);
        localStorage.setItem(ENC_DATA_KEY, JSON.stringify(encData));
    },

    getWorkerKey: async function() {
        return await getStoredKey();
    },

    restoreWorkerKey: async function(keyB64) {
        await setWorkerKey(keyB64);
    },

    destroy: async function() {
        await clearWorkerKey();
        localStorage.removeItem(SALT_KEY);
        localStorage.removeItem(ENC_RSA_KEY);
        localStorage.removeItem(ENC_PQC_KEY);
        localStorage.removeItem(ENC_DATA_KEY);
        sessionStorage.removeItem('admin_has_key');
        sessionStorage.removeItem('admin_priv_key');
        sessionStorage.removeItem('admin_pqc_priv_key');
        sessionStorage.removeItem('admin_data_key');
    }
};
})();
