const { sign } = require(`jsonwebtoken`);
const { Strategy: GitHubStrategy } = require(`passport-github2`);
const passport = require(`passport`);
const passportJwt = require(`passport-jwt`);
require(`isomorphic-fetch`);

const {
  BASE_URL,
  ENDPOINT,
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  SECRET,
  HASURA_ENDPOINT,
  // eslint-disable-next-line comma-dangle
  HASURA_SECRET
} = require(`./config`);

function authJwt(id) {
  return sign({ user: { id } }, HASURA_SECRET);
}

// eslint-disable-next-line no-console
console.log(`${BASE_URL}${ENDPOINT}/auth/github/callback`);

passport.use(
  new GitHubStrategy(
    {
      clientID: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
      callbackURL: `${BASE_URL}${ENDPOINT}/auth/github/callback`,
      // eslint-disable-next-line comma-dangle
      scope: [`user:email`]
    },
    async (accessToken, refreshToken, profile, done) => {
      fetch("https://hasura-jwt-oauth-prac.herokuapp.com/v1/graphql", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-hasura-admin-secret": `${process.env.HASURA_SECRET}`
        },
        body: JSON.stringify({
          query: `query {
          users(where: {github_user_id: {_eq: ${profile.id}}}) {
            access_token
            bio
            github_user_id
            id
            name
            public_gists
            public_repos
            refresh_token
          }
        }
        `
        })
      })
        // eslint-disable-next-line arrow-parens
        .then(res => res.json())
        .then(res => {
          if (res.data.users[0] !== undefined) {
            const claims = {
              sub: "" + res.data.users[0].id,
              "https://hasura.io/jwt/claims": {
                "x-hasura-default-role": "admin",
                "x-hasura-user-id": "" + res.data.users[0].id,
                "x-hasura-allowed-roles": ["admin", "user"]
              }
            };

            const jwt = authJwt(claims);
            const user = {
              id: res.data.users[0].id,
              userName: res.data.users[0].name
            };

            // req.user = user;
            console.log("jwt " + jwt);
            console.log("user" + user);
            const id = user.id;
            return done(null, { id, jwt });
          } else {
            var newUser;
            const query = `mutation (
              $github_user_id: Int!
              $name: String!
              $bio: String
              $pubic_repos: Int!
              $public_gists: Int!
              $access_token: String
              $refresh_token: String
            ) {
              insert_users(objects: {
              name: $name, 
              public_gists: $public_gists, 
              public_repos: $pubic_repos, 
              refresh_token: $refresh_token, 
              github_user_id: $github_user_id, 
              bio: $bio, 
              access_token: $access_token}) {
                returning {
                  access_token
                  bio
                  github_user_id
                  id
                  name
                  public_gists
                  public_repos
                  refresh_token
                }
              }
            }
             `;
            const variables = {
              github_user_id: profile._json.id,
              name: profile._json.name,
              bio: profile._json.bio,
              pubic_repos: profile._json.public_repos,
              public_gists: profile._json.public_gists,
              access_token: accessToken,
              refresh_token: refreshToken
            };
            fetch("https://hasura-jwt-oauth-prac.herokuapp.com/v1/graphql", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "x-hasura-admin-secret": "i30LbO4dZlwjW95R8cP+D8hZ2OktZSMN"
              },
              body: JSON.stringify({
                query,
                variables
              })
            })
              .then(res => res.json())
              .then(res => {
                console.log(res.data.insert_users);

                const claims = {
                  sub: "" + res.data.insert_users.returning[0].id,
                  "https://hasura.io/jwt/claims": {
                    "x-hasura-default-role": "admin",
                    "x-hasura-user-id":
                      "" + res.data.insert_users.returning[0].id,
                    "x-hasura-allowed-roles": ["admin", "user"]
                  }
                };
                const jwt = authJwt(claims);
                const user = {
                  id: res.data.insert_users.returning[0].id,
                  userName: res.data.insert_users.returning[0].name
                };

                // req.user = user;
                console.log("jwt " + jwt);
                console.log("user" + user);
                const id = user.id;
                return done(null, { id, jwt });
              });
          }
        });
    }
  )
);

passport.use(
  new passportJwt.Strategy(
    {
      jwtFromRequest(req) {
        if (!req.cookies) throw new Error(`Missing cookie-parser middleware`);
        return req.cookies.jwt;
      },
      secretOrKey: HASURA_SECRET
    },
    async ({ user: { id } }, done) => {
      try {
        // Here you'd typically load an existing user
        // and use their data to create the JWT.
        const jwt = authJwt(id);

        return done(null, { id, jwt });
      } catch (error) {
        return done(error);
      }
    }
  )
);
