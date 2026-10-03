const https = require('https');

function makeRequest(method, path, headers, body) {
  return new Promise((resolve) => {
    const opts = {
      hostname: 'vaultwarden-masterless-demo.lag0.com.br',
      path,
      method: method || 'GET',
      headers: headers || {},
      rejectUnauthorized: false,
    };
    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data.substring(0, 500) }));
    });
    req.on('error', e => resolve({ error: e.message }));
    if (body) req.write(body);
    req.end();
  });
}

async function main() {
  const paths = [
    '/api/config',
    '/api/accounts/profile',
    '/api/accounts/key-connector/confirmation-details/test-user-id',
    '/identity/connect/token',
    '/alive',
  ];
  const acceptHeaders = [
    'application/json',
    '*/*',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    '',
  ];
  
  for (const path of paths) {
    console.log('\n=== ' + path + ' ===');
    for (const accept of acceptHeaders) {
      const headers = accept ? { 'Accept': accept } : {};
      const r = await makeRequest('GET', path, headers);
      const label = accept ? accept.substring(0, 40) : '(none)';
      console.log('  Accept[' + label + '] => ' + r.status + ' : ' + r.body.substring(0, 150));
    }
  }
  
  // Also check WASM file
  console.log('\n=== /9a67ab1868d3d4316e23.module.wasm ===');
  const wasm = await makeRequest('GET', '/9a67ab1868d3d4316e23.module.wasm', {});
  console.log('Status:', wasm.status, 'Body:', wasm.body.substring(0, 200));
  console.log('Content-Type:', wasm.headers['content-type']);
}

main().catch(console.error);
