// db.js
require('dotenv').config();
const MongoClient = require('mongodb').MongoClient;

// MongoDB connection URL with authentication options
const url = process.env.MONGO_URL;
const dbName = process.env.MONGO_DB;

let dbInstance = null;

async function connectToDatabase() {
    if (dbInstance) {
        return dbInstance;
    }

    const client = new MongoClient(url);

    try {
        // Connect to MongoDB
        await client.connect();
        
        // Connect to the database and store the instance
        dbInstance = client.db(dbName);
        
        return dbInstance;
    } catch (error) {
        console.error('Error connecting to the database:', error);
        throw error; // Rethrow the error to handle it in the calling code
    }
}

module.exports = connectToDatabase;
