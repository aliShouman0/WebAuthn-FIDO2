const express = require('express');
const { generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');
const db = require('../db');
const router = express.Router();

const RP_ID = 'localhost';
const RP_NAME = 'WebAuthn';
const ORIGIN = 'http://localhost:3000';

// Generate Registration Options
router.post('/register/options', (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username required' });
    }

    db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        let userId;

        if (!user) {
            db.run('INSERT INTO users (username) VALUES (?)', [username], function (err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to create user' });
                }
                userId = this.lastID;
                generateAndSendOptions(userId, res);
            });
        } else {
            userId = user.id;
            generateAndSendOptions(userId, res);
        }
    });
});

//generate registration options
async function generateAndSendOptions(userId, res) {
    try {
        console.log('Generating options for userId:', userId);

        // Convert userId to Uint8Array (required in v13+)
        const userIdBuffer = Buffer.from(String(userId), 'utf-8');
        const userIdUint8Array = new Uint8Array(userIdBuffer);

        // v13+ returns a Promise, so we need to await it
        const options = await generateRegistrationOptions({
            rpName: RP_NAME,
            rpID: RP_ID,
            userName: `user_${userId}`,
            userID: userIdUint8Array,
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred',
            },
            timeout: 60000,
        });

        // Debug: Log the entire options object
        console.log('Generated options:', JSON.stringify(options, null, 2));
        console.log('Challenge type:', typeof options.challenge);
        console.log('Challenge value:', options.challenge);

        if (!options.challenge) {
            throw new Error('Failed to generate challenge - options.challenge is undefined');
        }

        // Store challenge in database with 5-minute expiry
        const challenge = options.challenge;
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        console.log('About to insert challenge:', {
            userId,
            challenge,
            challengeType: typeof challenge,
            challengeLength: challenge ? challenge.length : 0,
            type: 'registration',
            expiresAt: expiresAt.toISOString()
        });

        db.run(
            `INSERT INTO challenges (userId, challenge, type, expiresAt)
   VALUES (?, ?, ?, ?)`,
            [userId, challenge, 'registration', expiresAt.toISOString()],
            function (err) {
                if (err) {
                    console.error('Failed to store challenge:', err);
                    return res.status(500).json({ error: 'Failed to store challenge: ' + err.message });
                }

                console.log(`Registration challenge generated for user ${userId}`);
                res.json(options);
            }
        );
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}


//verify registration response
router.post('/register/verify', (req, res) => {
    const { username, response } = req.body;

    if (!username || !response) {
        return res.status(400).json({ error: 'Username and response required' });
    }

    try {
        // Get user 
        db.get('SELECT id FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            //Get the stored challenge not expired
            db.get(
                `SELECT challenge FROM challenges 
         WHERE userId = ? AND type = 'registration' 
         AND expiresAt > datetime('now')
         ORDER BY createdAt DESC LIMIT 1`,
                [user.id],
                async (err, challengeRow) => {
                    if (err) {
                        return res.status(500).json({ error: 'Database error' });
                    }

                    if (!challengeRow) {
                        return res.status(400).json({ error: 'No valid registration challenge found' });
                    }
                    const storedChallenge = challengeRow.challenge;
                    try {
                        //Verify the registration response (cryptographic verification)
                        const verification = await verifyRegistrationResponse({
                            response,
                            expectedChallenge: storedChallenge,
                            expectedOrigin: ORIGIN,
                            expectedRPID: RP_ID,
                        });

                        //Check verification
                        if (!verification.verified) {
                            return res.status(400).json({ error: 'Verification failed' });
                        }

                        // Debug: Log the verification response
                        console.log('Verification successful!');

                        // Extract credential from nested structure (v13+)
                        const { credential } = verification.registrationInfo;
                        const { id, publicKey, counter, transports } = credential;

                        //Store credential in database
                        // id is already base64url string in v13, publicKey is Uint8Array
                        const credentialIDBase64 = id;
                        const publicKeyBuffer = Buffer.from(publicKey);

                        db.run(
                            `INSERT INTO credentials (userId, credentialID, publicKey, counter, transports)
               VALUES (?, ?, ?, ?, ?)`,
                            [user.id, credentialIDBase64, publicKeyBuffer, counter, JSON.stringify(transports || [])],
                            (err) => {
                                if (err) {
                                    return res.status(500).json({ error: 'Failed to store credential' });
                                }

                                //Delete the used challenge (single-use enforcement)
                                db.run(
                                    'DELETE FROM challenges WHERE userId = ? AND type = "registration"',
                                    [user.id],
                                    (err) => {
                                        if (err) {
                                            console.error('Warning: Failed to delete challenge:', err);
                                        }

                                        console.log(`Passkey registered successfully for user ${user.id}`);
                                        res.json({
                                            verified: true,
                                            message: 'Passkey registered successfully'
                                        });
                                    }
                                );
                            }
                        );

                    } catch (error) {
                        console.error('Verification error:', error);
                        res.status(400).json({ error: 'Cryptographic verification failed: ' + error.message });
                    }
                }
            );
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;