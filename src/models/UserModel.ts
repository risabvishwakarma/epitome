import mongoose, { Document, Schema, Model, CallbackError } from 'mongoose';
import bcrypt from 'bcryptjs'

// Define interface for user document
export interface IUser extends Document {
    name: string;
    email: string;
    password: string;
    role: 'Admin' | 'Client' | 'User'; // Define roles
    resetPasswordToken?: string;
    resetPasswordExpires?: Date;
    haveSubscription: boolean;
    subscriptionExpiry: Date | undefined;
    comparePassword: (password: string) => Promise<boolean>;
}

// Define user schema
const userSchema: Schema<IUser> = new Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ['Admin', 'Client', 'User'],
        default: 'User',
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    haveSubscription: Boolean,
    subscriptionExpiry: Date,
});

// Pre-save hook to hash password
userSchema.pre<IUser>('save', async function (next) {
    if (!this.isModified('password')) return next(); // Only hash if password is modified
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error as CallbackError); // Type casting the error to CallbackError
    }
});

// Password comparison method
userSchema.methods.comparePassword = async function (password: string): Promise<boolean> {
    return bcrypt.compare(password, this.password);
};

// Create and export User model
const User: Model<IUser> = mongoose.model<IUser>('User', userSchema);

export default User;
