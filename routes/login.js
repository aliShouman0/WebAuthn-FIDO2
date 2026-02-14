const express = require('express');
const { generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const db = require('../db');

const router = express.Router();
const RP_ID = 'localhost';
const ORIGIN = 'http://localhost:3000';


router.post('/login/options', (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }

  db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    //Get user's registered credentials
    db.all(
      'SELECT credentialID, transports FROM credentials WHERE userId = ?',
      [user.id],
      async (err, credentials) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }

        if (!credentials || credentials.length === 0) {
          return res.status(400).json({ error: 'No passkeys registered for this user' });
        }

        try {
          //Generate authentication options with allowed credentials
          // v13+ is async and credentialID is already base64url string
          const options = await generateAuthenticationOptions({
            rpID: RP_ID,
            allowCredentials: credentials.map(cred => ({
              id: cred.credentialID, // Already base64url in v13
              transports: JSON.parse(cred.transports || '[]'),
            })),
          });

          //Store challenge in database with 5-minute expiry
          const challenge = options.challenge;
          const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

          db.run(
            `INSERT INTO challenges (userId, challenge, type, expiresAt)
             VALUES (?, ?, ?, ?)`,
            [user.id, challenge, 'authentication', expiresAt.toISOString()],
            (err) => {
              if (err) {
                return res.status(500).json({ error: 'Failed to store challenge' });
              }

              console.log(`Login challenge generated for user ${user.id}`);
              res.json(options);
            }
          );

        } catch (error) {
          res.status(500).json({ error: error.message });
        }
      }
    );
  });
});


//Verify Login Response
router.post('/login/verify', (req, res) => {
  const { username, response } = req.body;

  if (!username || !response) {
    return res.status(400).json({ error: 'Username and response required' });
  }

  try {
    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      //  Get the stored  challenge 
      db.get(
        `SELECT challenge FROM challenges 
         WHERE userId = ? AND type = 'authentication' 
         AND expiresAt > datetime('now')
         ORDER BY createdAt DESC LIMIT 1`,
        [user.id],
        async (err, challengeRow) => {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }

          if (!challengeRow) {
            return res.status(400).json({ error: 'No valid login challenge found' });
          }

          const storedChallenge = challengeRow.challenge;

          try {
            //  Get the credential used in the response
            const credentialID = response.id;

            db.get(
              'SELECT publicKey, counter FROM credentials WHERE credentialID = ?',
              [credentialID],
              async (err, credential) => {
                if (err) {
                  return res.status(500).json({ error: 'Database error' });
                }

                if (!credential) {
                  return res.status(400).json({ error: 'Credential not found' });
                }

                try {
                  // Verify the authentication response (v13+ format)
                  const verification = await verifyAuthenticationResponse({
                    response,
                    expectedChallenge: storedChallenge,
                    expectedOrigin: ORIGIN,
                    expectedRPID: RP_ID,
                    credential: {
                      id: credentialID, // Already base64url string
                      publicKey: new Uint8Array(credential.publicKey),
                      counter: credential.counter,
                    },
                  });

                  //  Check if verification succeeded
                  if (!verification.verified) {
                    return res.status(400).json({ error: 'Authentication failed' });
                  }

                  //  Counter Validation
                  const newCounter = verification.authenticationInfo.newCounter;
                  const oldCounter = credential.counter;

                  if (newCounter <= oldCounter) {
                    console.error(` CLONING DETECTED: Counter not incremented for credential ${credentialID}`);
                    return res.status(400).json({
                      error: 'Authentication failed: Possible authenticator cloning detected',
                      details: 'Counter did not increment  authenticator may be compromised'
                    });
                  }

                  // Update counter in database
                  db.run(
                    'UPDATE credentials SET counter = ? WHERE credentialID = ?',
                    [newCounter, credentialID],
                    (err) => {
                      if (err) {
                        console.error('Warning: Failed to update counter:', err);
                      }
                    }
                  );

                  // Delete the used challenge (single-use enforcement)
                  db.run(
                    'DELETE FROM challenges WHERE userId = ? AND type = "authentication"',
                    [user.id],
                    (err) => {
                      if (err) {
                        console.error('Warning: Failed to delete challenge:', err);
                      }

                      //  Create session token
                      const sessionToken = Buffer.from(`${user.id}:${Date.now()}`).toString('base64');

                      console.log(` Login successful for user ${user.id} (counter: ${oldCounter} ---- ${newCounter})`);
                      res.json({
                        verified: true,
                        message: 'Authentication successful',
                        token: sessionToken,
                        userId: user.id
                      });
                    }
                  );

                } catch (error) {
                  console.error('Verification error:', error);
                  res.status(400).json({ error: 'Cryptographic verification failed: ' + error.message });
                }
              }
            );

          } catch (error) {
            res.status(500).json({ error: error.message });
          }
        }
      );
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;