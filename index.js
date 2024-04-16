const { getConfig } = require('@pei-media/pei-config');
const fs = require('fs');
const crypto = require('crypto');
const superagent = require('superagent');

class HmacSigner {
  constructor() {
    this.algorithm = 'sha256';
  }

  signRequest(secretKey, path, method, timestamp, nonce, body) {
    if (!secretKey) throw new Error('Client secret must be provided');
    if (!path) throw new Error('Request path must be provided');
    if (!method) throw new Error('Request method must be provided');
    if (!timestamp) throw new Error('Signature timestamp must be provided');
    if (!nonce) throw new Error('Signature nonce must be provided');

    if (body && typeof body === 'object') {
      body = JSON.stringify(body);
    }

    let hash = crypto
      .createHash(this.algorithm)
      .update(secretKey)
      .update(body)
      .update(path)
      .update(method)
      .update(timestamp.toString())
      .update(nonce)
      .digest('hex');
    return hash;
  }
}

function getBlaizeAuthHeader(path, method, hostConfig, body = '') {
  if (!(hostConfig && hostConfig.hasOwnProperty('accessKey') && hostConfig.hasOwnProperty('accessKey'))) {
    throw Error('Zephr credentials not provided');
  }

  const accessKey = hostConfig.accessKey;
  const secretKey = hostConfig.secretKey;
  const timestamp = new Date().getTime();
  const nonce = Math.random().toString();

  const hash = new HmacSigner('sha256').signRequest(secretKey, path, method, timestamp, nonce, body);
  return `BLAIZE-HMAC-SHA256 ${accessKey}:${timestamp}:${nonce}:${hash}`;
}

(async () => {
  const config = await getConfig();
  // IMPORTANT
  // its enough to get one brnad because all of them are sharing users
  const brand = config.brandsConfig[0];
  const hostConfig = {
    adminUrl: brand.blaize.adminUrl,
    accessKey: config.secrets.blaize.accessKey,
    secretKey: config.secrets.blaize.secretKey,
  };
  const { body } = await superagent
    .get(`${hostConfig.adminUrl}/v3/user-export?attributes=true`)
    .set('Content-Type', 'application/json')
    .set('Accept', 'application/json')
    .set('Authorization', getBlaizeAuthHeader('/v3/user-export', 'GET', hostConfig));

  const users = body.filter(u => Object.keys(u.user.attributes).length > 0);
  console.log(`Fetched all users. Count: ${users.length}`);
  const report = {
    time: {},
    userWithErrors: [],
  };
  let counter = 0;
  report.time.start = new Date().getTime();
  for (let u of users) {
    try {
      await superagent
        .put(`${hostConfig.adminUrl}/v3/users/${u.user.user_id}/foreign-key/update/crmIdentifier`)
        .set('Content-Type', 'application/json')
        .set('Accept', 'application/json')
        .set(
          'Authorization',
          getBlaizeAuthHeader(
            `/v3/users/${u.user.user_id}/foreign-key/update/crmIdentifier`,
            'PUT',
            hostConfig,
            u.user.attributes.crmIdentifier,
          ),
        )
        .send(u.user.attributes.crmIdentifier);
    } catch (e) {
      report.userWithErrors.push(u.user.identifiers.email_address);
      console.log(e);
    }

    counter++;
    if (counter % 100 === 0) {
      console.log(`Processed users: ${counter}/${users.length}`);
    }
  }
  report.time.end = new Date().getTime();

  fs.writeFileSync('foreign-key-creation-report.json', JSON.stringify(report));
})();
