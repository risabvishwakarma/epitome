import express from 'express';
import connectDB from './database/MongoConfig';
import dotenv from 'dotenv';
import authRoutes from './router/UserRouter'; // Import the router

import cookieParser from 'cookie-parser'; // Correct import

// Load environment variables from .env file
dotenv.config();

// Initialize the Express application
const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
connectDB();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Use authentication routes
app.use('/api/auth', authRoutes); // Prefix routes with /api/auth

// Basic route
// app.get('/', (req, res) => {
//     res.send('Hello, MongoDB with TypeScript!');
// });

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
