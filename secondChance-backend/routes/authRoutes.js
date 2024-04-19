require('dotenv').config();
const express = require('express');
const router = express.Router();
const logger = require("../logger");
const connectToDatabase = require("../models/db");
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { body, validationResult } = require('express-validator');
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
        // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
        const db = await connectToDatabase();

        // Task 2: Access MongoDB `users` collection
        const collection = db.collection('users');

        // Task 3: Check if user credentials already exists in the database and throw an error if they do
        const email = req.body.email;
        const existingEmail = await collection.findOne({ email: email });
        
        if(existingEmail){
            logger.error('Email id already exists');
            return res.status(400).json({ error: 'Email id already exists' });
        }

        // Task 4: Create a hash to encrypt the password so that it is not readable in the database
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);

        // Task 5: Insert the user into the database
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });
        // Task 6: Create JWT authentication if passwords match with user._id as payload
        const payload = {
            user: {
                id: newUser.insertedId,
            }
        }

        const authToken = jwt.sign(payload, JWT_SECRET);

        // Task 7: Log the successful registration using the logger
        logger.info('User registered succesfully');

        // Task 8: Return the user email and the token as a JSON
        res.json({ authToken, email})
    } catch (e) {
         return res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req, res) => {
    try {
        // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
        const db = await connectToDatabase();

        // Task 2: Access MongoDB `users` collection
        const collection = db.collection('users');

        // Task 3: Check for user credentials in database
        const { email, password } = req.body;
        const theUser = await collection.findOne({email: email});

        // Task 4: Check if the password matches the encrypted password and send appropriate message on mismatch
        if(theUser) {
            let result = await bcryptjs.compare(password, theUser.password);
            if(!result){
                logger.error('Password do not match');
                return res.json(404).json({ error: 'Wrong password' });
            }

            // Task 5: Fetch user details from a database
            const { userName, userEmail } = theUser;

            let payload = {
                user: {
                    id: theUser._id.toString()
                }
            };

            // Task 6: Create JWT authentication if passwords match with user._id as payload
            const authToken = jwt.sign(payload, JWT_SECRET);

            res.json({authToken, userName, userEmail });
        } else {
            // Task 7: Send appropriate message if the user is not found
            logger.error('User not found');
            return res.json(404).json({ error: 'User not found.' });
        }

    } catch (e) {
        logger.error(e)
         return res.status(500).send('Internal server error');

    }
});

router.put('/update', async (req, res) => {
    // Task 2: Validate the input using `validationResult` and return an appropriate message if you detect an error
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.error('Validation errors in update request', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        // Task 3: Check if `email` is present in the header and throw an appropriate error message if it is not present
        const email = req.headers.email; 
        if(!email){
            logger.error('Email not found in the request header')
        }
        // Task 4: Connect to MongoDB
        const db = await connectToDatabase();
        const collection = db.collection('users');

        // Task 5: Find the user credentials in database
        const existingUser = await collection.findOne({ email: email });
        if (!existingUser) {
            logger.error('User not found');
            return res.status(404).json({ error: "User not found" });
        }
        existingUser.firstName = req.body.name;
        existingUser.updatedAt = new Date();

        // Task 6: Update the user credentials in the database
        const updateUser = await collection.findOneAndUpdate(
            { email },
            { $set: existingUser },
            { returnDocument: 'after' }
        );

        // Task 7: Create JWT authentication with `user._id` as a payload using the secret key from the .env file
        const payload = {
            user: {
                id: updateUser._id.toString()
            }
        }

        const authToken = jwt.sign(payload, JWT_SECRET);
        logger.info('User updated successfully');
        res.json({ authToken });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error');
    }
});

module.exports = router;