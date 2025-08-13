const net = require('net');

const socketPath = process.env.VULTISIG_SOCKET || process.env.MPC_SOCKET || '/tmp/vultisig.sock';

function run() {
  return new Promise((resolve, reject) => {
    const client = net.createConnection({ path: socketPath }, () => {
      const req = { id: 42, method: 'get_address', params: { scheme: 'ecdsa', curve: 'secp256k1', network: 'eth' } };
      client.write(JSON.stringify(req) + '\n');
    });

    let buffer = '';
    client.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line);
          console.log('Address response:', JSON.stringify(msg));
          client.end();
          resolve();
        } catch (e) {
          console.error('Invalid JSON:', line);
          client.end();
          reject(e);
        }
      }
    });

    client.on('error', (err) => {
      console.error('Socket error:', err.message);
      reject(err);
    });
  });
}

run().catch(() => process.exit(1));


