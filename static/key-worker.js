let storedKey = null;

onconnect = function(e) {
  const port = e.ports[0];

  port.onmessage = function(event) {
    const { type, key, messageId } = event.data;

    if (type === 'set-key') {
      storedKey = key;
      port.postMessage({ ok: true, messageId });
    } else if (type === 'get-key') {
      port.postMessage({ key: storedKey, messageId });
    } else if (type === 'clear-key') {
      storedKey = null;
      port.postMessage({ ok: true, messageId });
    }
  };
};
