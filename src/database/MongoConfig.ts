import mongoose from 'mongoose';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

// Connect to MongoDB
const connectDB = async (): Promise<void> => {
    try {
        // Connect to MongoDB with updated Mongoose settings
        await mongoose.connect(process.env.MONGO_URI as string, {
            // Mongoose automatically handles default options, so you can omit these unless needed
        });
        console.log('MongoDB connected');
    } catch (error) {
        // Error handling
        if (error instanceof Error) {
            console.error('Error connecting to MongoDB:', error.message);
        } else {
            console.error('Unknown error connecting to MongoDB');
        }
        process.exit(1); // Exit process with failure
    }
};

export default connectDB;
