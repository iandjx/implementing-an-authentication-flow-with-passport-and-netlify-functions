/* prettier-ignore */
exports.BASE_URL = process.env.NODE_ENV === `development` ? `http://localhost:8888` : process.env.BASE_URL;
// exports.BASE_URL = process.env.BASE_URL;

exports.COOKIE_SECURE = process.env.NODE_ENV !== `development`;
/* prettier-ignore */
exports.ENDPOINT = process.env.NODE_ENV === `development` ? `/.netlify/functions` : `/api`;

exports.GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
exports.GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;

exports.SECRET = process.env.SECRET || `SUPERSECRET`;
exports.HASURA_ENDPOINT = process.env.HASURA_ENDPOINT;
exports.HASURA_SECRET = process.env.HASURA_SECRET;
