import express from 'express';
import connectDB from './database/MongoConfig';
import dotenv from 'dotenv';
import authRoutes from './router/UserRouter'; // Import the router

import cookieParser from 'cookie-parser'; // Correct import

import cors from 'cors'
import { UserRegistrationMapSingleton } from './application/RegistrationTemp';

// Load environment variables from .env file
dotenv.config();

// Initialize the Express application
const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
connectDB();
app.use(cors());
// Middleware
app.use(express.json());
app.use(cookieParser());

// Use authentication routes
app.use('/api/auth', authRoutes); // Prefix routes with /api/auth

// Basic route
app.get('/kaisan-waa', (req, res) => {
    res.send('Baki sab theek, Bass chall rha hai🙌');
});



// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
