import { Request, Response } from 'express';
import User from '../models/UserModel';
import jwt from 'jsonwebtoken'; // Import jwt
import crypto from 'crypto'; // Import crypto module for generating tokens
import nodemailer from 'nodemailer'; // Import nodemailer for sending emails
class UserController {
    public async profile(req: Request, res: Response): Promise<void> {
        const user = (req as any).user;
        res.json({ message: 'Profile data 😀', user }); // Incorrectly returns Response object
    }
    public async home(req: Request, res: Response): Promise<void> {
        res.status(200).json({ message: 'Hello!!' });
    }

    public async registerUser(req: Request, res: Response): Promise<void> {
        try {
            console.log(req.body)
            const { name, email, password, role } = req.body;

            // Check if user already exists
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                res.status(400).json({ message: 'User already exists' });
                return;
            }

            // Create new user
            const newUser = new User({ name, email, password, role });

            console.log("new user ",newUser)

            const savedUser = await newUser.save();

            // Respond with user data
            res.status(201).json({ id: savedUser._id, name: savedUser.name, email: savedUser.email, role: savedUser.role   });
        } catch (error) {
            res.status(500).json({ message: 'Error registering user' });
        }
    }

    public async loginUser(req: Request, res: Response): Promise<void> {
        try {
            const { email, password } = req.body;

            // Find user
            const user = await User.findOne({ email });
            if (!user) {
                res.status(401).json({ message: 'Invalid credentials' });
                return;
            }

            // Check password
            const isMatch = await user.comparePassword(password);
            if (!isMatch) {
                res.status(401).json({ message: 'Invalid credentials' });
                return;
            }

            // Generate JWT token with role
            const token = jwt.sign(
                { userId: user.id, role: user.role }, // Include user role in token
                process.env.JWT_SECRET as string,
                { expiresIn: process.env.SESSION_EXPIRY }
            );

            console.log("login "+token)
                  // Save token in cookies
                  res.cookie('token', token, {
                    httpOnly: true,
                    maxAge: Number(process.env.COOKIE_AGE) * 3600000, // COOKIE_AGE in hours
                    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
                    sameSite: 'strict',
                });           

            // Respond with token
            res.status(200).json({ token });
        } catch (error ) {
            res.status(500).json({ message: 'Error logging in', error: error });
        }
    }

    // Other methods...

    public async forgotPassword(req: Request, res: Response): Promise<void> {
        try {
            const { email } = req.body;
    
            // Find the user
            const user = await User.findOne({ email });
            if (!user) {
                res.status(404).json({ message: 'User not found' });
                return;
            }
    
            // Generate a reset token
            const resetToken = crypto.randomBytes(20).toString('hex');
    
            // Set token and expiration in the user document
            user.resetPasswordToken = resetToken;
            user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour
            await user.save();
    
            // Send reset token to user via email
            const transporter = nodemailer.createTransport({
                service: 'Gmail', // or another email service
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
            });
    
            const resetURL = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
            const mailOptions = {
                to: email,
                from: process.env.EMAIL_USER,
                subject: 'Password Reset',
                text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\nPlease make a PUT request to the following URL to reset your password:\n\n${resetURL}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.\n`,
            };
    
            await transporter.sendMail(mailOptions);
    
            res.status(200).json({ message: 'Password reset token sent to email' });
        } catch (error) {
            res.status(500).json({ message: 'Error processing request', error: error });
        }
    }
    

    public async resetPassword(req: Request, res: Response): Promise<void> {
        try {

            const { token , newPassword } = req.body;

            // Find user by reset token
            const user = await User.findOne({
                resetPasswordToken: token,
                resetPasswordExpires: { $gt: Date.now() },
            });
            if (!user) {
                res.status(400).json({ message: 'Password reset token is invalid or has expired' });
                return;
            }

            // Set new password and clear reset token
            user.password = newPassword;
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            await user.save();

            res.status(200).json({ message: 'Password has been updated' });
        } catch (error) {
            res.status(500).json({ message: 'Error resetting password', error: error });
        }
    }


    public async checkSubscriptionStatus(req: Request, res: Response): Promise<void> {
        try {
            const userId = (req as any).userId;

            console.log(userId)

            const user=await User.findById(userId);

            if(null==user){
                res.status(200).json({ message: 'user not found' });
                return;
            }

            if (!user.haveSubscription) {
                res.status(200).json({ message: 'No active subscription' });
                return;
            }

            if (user.subscriptionExpiry && new Date(user.subscriptionExpiry).getTime() < Date.now()) {
                res.status(200).json({ message: 'Subscription has expired' });
                return;
            }

            res.status(200).json({ message: 'Subscription is active' });
        } catch (error) {
            res.status(500).json({ message: 'Error checking subscription status', error });
        }
    }

    // Method to renew subscription
    public async renewSubscription(req: Request, res: Response): Promise<void> {
        try {
            const userId = (req as any).userId;

            console.log(userId)

            const user=await User.findById(userId);

            if(null==user){
                res.status(200).json({ message: 'user not found' });
                return;
            }

            // Renew the subscription (for example, extend by 1 month)
            user.haveSubscription = true;
            user.subscriptionExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // Extend by 30 days

            await user.save();

            res.status(200).json({ message: 'Subscription has been renewed', subscriptionExpiry: user.subscriptionExpiry });
        } catch (error) {
            res.status(500).json({ message: 'Error renewing subscription', error });
        }
    }

    // Method to cancel subscription
    public async cancelSubscription(req: Request, res: Response): Promise<void> {
        try {
            const userId = (req as any).userId;

            console.log(userId)

            const user=await User.findById(userId);

            if(null==user){
                res.status(200).json({ message: 'user not found' });
                return;
            }

            // Cancel the subscription
            user.haveSubscription = false;
            user.subscriptionExpiry = undefined;

            await user.save();

            res.status(200).json({ message: 'Subscription has been canceled' });
        } catch (error) {
            res.status(500).json({ message: 'Error canceling subscription', error });
        }
    }


    public async logoutUser(req: Request, res: Response): Promise<void> {
        // For JWT, you usually handle logout on the client side
        // The server doesn’t need to do anything for logout, but you could
        // implement functionality like token blacklist or expire tokens

        res.status(200).json({ message: 'Logged out successfully' });
    }
}

export default UserController;
